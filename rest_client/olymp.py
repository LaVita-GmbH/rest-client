from json.decoder import JSONDecodeError
import logging
import re
from urllib.parse import urlencode
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
from jose import jwt
from jsonpath_ng import parse as jsonpath_parse
from requests.exceptions import RetryError
from . import Client


_logger = logging.getLogger(__name__)


class OlympClient(Client):
    DEFAULT_AUTH = 'transaction'

    class Endpoint(Client.Endpoint):
        def __init__(self, client, path=[]):
            super().__init__(client, path=path)
            self.endpoint = "/" + "/".join([str(el).replace('_', '-') for el in self.path])

    class Request(Client.Request):
        def __init__(self, client, method, endpoint, timeout: Optional[int], return_plain_response: bool, other_ok_states: Optional[Tuple[int]], referenced_data_load=None, **kwargs):
            if 'auth' in kwargs:
                self.auth = kwargs.pop('auth')

            else:
                self.auth = client.DEFAULT_AUTH

            self._referenced_data_load = referenced_data_load

            super().__init__(client, method, endpoint, timeout=timeout, return_plain_response=return_plain_response, other_ok_states=other_ok_states, **kwargs)

        def _get_headers(self) -> dict:
            headers = super()._get_headers()

            if self.auth:
                if not self.client._tokens.get(self.auth):
                    getattr(self.client, f'auth_{self.auth}')()

                headers['Authorization'] = self.client._tokens[self.auth]

            return headers

        def _handle_response(self):
            if self._response.status_code == 401:
                if self._response_data and self._response_data.get('detail', {}).get('type') == 'ExpiredSignatureError':
                    # Token has expired, retry request
                    # delete  token so a new token is fetched before doing the action request
                    del self.client._tokens[self.auth]
                    raise RetryError

            if self._response.status_code == 404 and self.retry <= self.max_retry:
                if self._response_data and self._response_data.get('detail', {}).get('type') == 'DoesNotExist':
                    raise RetryError

            if self._response.status_code == 420 and self.retry <= self.max_retry:
                if self._response_data and self._response_data.get('detail', {}).get('type') == 'IntegrityError' \
                    and self._response_data.get('detail', {}).get('code').startswith('foreign_key_violation:'):
                    raise RetryError

            if self.return_plain_response:
                return self._response

            if not self._response.ok and self._response.status_code not in self.other_ok_states:
                if self._response_data:
                    if self._response.status_code == 422:
                        raise self.APIError(self, "ValidationError", self._response_data)

                    error_type = self._response_data.get('detail', {}).get('type') if self._response_data else "Unknown"
                    raise self.APIError(self, error_type, self._response_data)

                raise self.APIError(self, self._response.text)

            if self._response_data:
                if (self.client._referenced_data_auto_load and self._referenced_data_load is not False) or self._referenced_data_load:
                    self.client.load_referenced_data(self._response_data)

                return self._response_data

            return None

    def __init__(
        self,
        url,
        *,
        timeout=10,
        verify=True,
        user: Optional[Tuple[str,
        str,
        str]] = None,
        access_token: Optional[str] = None,
        referenced_data_auto_load: bool = False,
        referenced_data_clients: Optional[Dict[str, Dict[str, Client]]] = None,
        referenced_data_expire: timedelta = timedelta(seconds=3600),
        include_critical: bool = False,
    ):
        assert user or access_token, "user or access_token must be given"

        super().__init__(url, timeout=timeout, verify=verify)

        self._user = user
        self._access_token = access_token
        self._include_critical = include_critical
        self._tenant_id = self._user[2] if self._user else None
        self._referenced_data_auto_load = referenced_data_auto_load
        self._ext_clients: 'defaultdict[str, Dict[str, Client]]' = defaultdict(dict)
        if referenced_data_clients:
            self._ext_clients.update(referenced_data_clients)

        self._referenced_data_cache = {}
        self._referenced_data_expire = referenced_data_expire
        self._tokens = {}

    @property
    def tenant_id(self):
        if not self._tenant_id:
            if not self._tokens.get('transaction'):
                self.auth_transaction()

            claims = jwt.decode(self._tokens['transaction'], key=None, options={'verify_signature': False, 'verify_aud': False})
            self._tenant_id = claims.get('ten')

        return self._tenant_id

    def _load_related_data(self, relation: str, tenant_id: str, curr_obj: dict, id: Optional[str] = None, _cache: Optional[dict] = None, **lookup):
        if _cache is None:
            _cache = {}

        relation_location = relation.split('/')
        try:
            client: Client = self._ext_clients[relation_location[0]][tenant_id]

        except KeyError:
            _logger.warn("Cannot load data for $rel='%s' with tenant_id='%s'", relation, tenant_id)
            return

        else:
            endpoint = client
            def resolve_path(match):
                try:
                    result = jsonpath_parse(match.group(1)).find(curr_obj)[0]
                    return result.value

                except IndexError:
                    pass

            def resolve_placeholder(value):
                if not isinstance(value, str):
                    return value

                return re.sub(
                    r'\{([^\}]+)\}',
                    resolve_path,
                    value,
                )

            for loc in relation_location[1:]:
                try:
                    loc = resolve_placeholder(loc)

                except IndexError:
                    _logger.warn("Cannot resolve loc='%s' for $rel='%s' with tenant_id='%s'", loc)
                    return

                endpoint = getattr(endpoint, loc)

            def get_params() -> str:
                if '$rel_params' not in curr_obj:
                    return ''

                return f'?{urlencode(curr_obj["$rel_params"])}'

            cache_key = f'{tenant_id}@{relation}'
            if id:
                cache_key += f'/{id}{get_params()}'
                if cache_key not in _cache or datetime.utcnow() - _cache[cache_key][1] > self._referenced_data_expire:
                    try:
                        data = endpoint[id].get(referenced_data_load=False)
                        _cache[cache_key] = (data, datetime.utcnow())
                        self.load_referenced_data(data, clear_cache=False, parent=curr_obj)

                    except self.Request.APIError as error:
                        _logger.warn("Failed to load referenced data for $rel='%s' with tenant_id='%s', error: %r", relation, tenant_id, error, exc_info=True)
                        return

            elif '$rel_params' in curr_obj:
                cache_key += get_params()
                params = {key: resolve_placeholder(value) for key, value in curr_obj['$rel_params'].items()}
                if curr_obj.get('$rel_is_lookup'):
                    params['limit'] = 1

                try:
                    objects = endpoint.get(params=params)

                except self.Request.APIError as error:
                    _logger.warn("Failed to load referenced data for $rel='%s' with tenant_id='%s', error: %r", relation, tenant_id, error, exc_info=True)
                    return

                if curr_obj.get('$rel_is_lookup'):
                    cache_key += '[0]'
                    try:
                        _cache[cache_key] = (objects[loc][0], datetime.utcnow())

                    except (KeyError, IndexError) as error:
                        _logger.warn("Failed to get object from lookup for $rel='%s' with tenant_id='%s', error: %r", relation, tenant_id, error, exc_info=True)
                        return

                else:
                    _cache[cache_key] = (objects, datetime.utcnow())

            else:
                raise NotImplementedError

            return _cache[cache_key]

    def load_referenced_data(self, values: dict, clear_cache: bool = False, parent: Optional[dict] = None):
        """
        Load referenced data into `values`, performing an in-place update.
        """
        if clear_cache:
            self._referenced_data_cache = {}

        self._ext_clients['olymp'][self.tenant_id] = self

        def enrich_data(values, parent: Optional[dict] = None):
            if isinstance(values, list):
                for item in values:
                    enrich_data(item, parent=parent)

            if not isinstance(values, dict):
                return

            if parent:
                values['_parent'] = parent

            update = None
            time: datetime = None

            for key, value in list(values.items()):
                if key == '_parent':
                    continue

                if key == '$rel':
                    related = self._load_related_data(value, tenant_id=self.tenant_id, curr_obj=values, **values, _cache=self._referenced_data_cache)
                    if related:
                        update, time = related

                else:
                    enrich_data(value, parent=values)

            if update:
                enrich_data(update, parent=values)
                values.update(update)
                values['$rel_at'] = time.isoformat()

            if parent:
                del values['_parent']

        enrich_data(values, parent=parent)

    def auth_user(self):
        data = self.access.auth.user.post(auth=None, json={
            'email': self._user[0],
            'password': self._user[1],
            'tenant': {
                'id': self._user[2],
            },
        })

        self._tokens['user'] = data['token']['user']

    def auth_transaction(self):
        try:
            data = self.access.auth.transaction.post(referenced_data_load=False, auth=None if self._access_token else 'user', json={
                'access_token': self._access_token,
                'include_critical': self._include_critical,
            })

        except self.Request.APIError as error:
            if error.response:
                try:
                    data = error.response.json()
                    if data['error']['type'] == 'AuthError' and data['error']['code'] == 'token_too_old_for_include_critical':
                        del self._tokens['user']
                        return self.auth_transaction()

                    else:
                        raise error

                except JSONDecodeError:
                    raise error

            else:
                raise error

        self._tokens['transaction'] = data['token']['transaction']
