import logging
from typing import Dict, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
from . import Client
from jose import jwt


_logger = logging.getLogger(__name__)


class OlympClient(Client):
    DEFAULT_AUTH = 'transaction'

    class Request(Client.Request):
        def __init__(self, client, method, endpoint, timeout: Optional[int], return_plain_response: bool, other_ok_states: Optional[Tuple[int]], **kwargs):
            if 'auth' in kwargs:
                self.auth = kwargs.pop('auth')

            else:
                self.auth = client.DEFAULT_AUTH

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
                if self._response_data and self._response_data.get('detail', {}).get('type') in 'ExpiredSignatureError':
                    # Token has expired, retry request
                    # delete  token so a new token is fetched before doing the action request
                    del self.client._tokens[self.auth]

                    return self.perform()

            if self.return_plain_response:
                return self._response

            if not self._response.ok and self._response.status_code not in self.other_ok_states:
                if self._response_data:
                    error_type = self._response_data.get('detail', {}).get('type') if self._response_data else "Unknown"
                    raise self.APIError(self, error_type, self._response_data)

                raise self.APIError(self, self._response.text)

            if self._response_data:
                if self.client._referenced_data_auto_load:
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
    ):
        assert user or access_token, "user or access_token must be given"

        super().__init__(url, timeout=timeout, verify=verify)

        self._user = user
        self._access_token = access_token
        self._tenant_id = self._user[2] if self._user else None
        self._referenced_data_auto_load = referenced_data_auto_load
        self._ext_clients: 'defaultdict[str, Dict[str, Client]]' = defaultdict(dict)
        self._ext_clients.update(referenced_data_clients)
        self._referenced_data_cache = {}
        self._referenced_data_expire = referenced_data_expire
        self._tokens = {}

    @property
    def tenant_id(self):
        if not self._tenant_id:
            if not self._tokens.get('transaction'):
                self.auth_transaction()

            claims = jwt.decode(self._tokens['transaction'], options={'verify_signature': False})
            self._tenant_id = claims.get('ten')

        return self._tenant_id

    def _load_related_data(self, relation: str, tenant_id: str, id: Optional[str] = None, _cache: Optional[dict] = None, **lookup):
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
            for loc in relation_location[1:]:
                endpoint = getattr(endpoint, loc)

            cache_key = f'{relation}@{tenant_id}/'
            if id:
                cache_key += id
                if cache_key not in _cache or datetime.utcnow() - _cache[cache_key][1] > self._referenced_data_expire:
                    _cache[cache_key] = (endpoint[id].get(), datetime.utcnow())

                return _cache[cache_key]

            else:
                raise NotImplementedError

    def load_referenced_data(self, values: dict, clear_cache: bool = False):
        """
        Load referenced data into `values`, performing an in-place update.
        """
        if clear_cache:
            self._referenced_data_cache = {}

        self._ext_clients['olymp'][self.tenant_id] = self

        def enrich_data(values):
            if isinstance(values, list):
                for item in values:
                    enrich_data(item)

            if not isinstance(values, dict):
                return

            update = None
            time: datetime = None

            for key, value in values.items():
                if key == '$rel':
                    update, time = self._load_related_data(value, **values, _cache=self._referenced_data_cache)

                else:
                    enrich_data(value)

            if update:
                enrich_data(update)
                values.update(update)
                values['$rel_at'] = time.isoformat()

        enrich_data(values)

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
        data = self.access.auth.transaction.post(auth=None if self._access_token else 'user', json={
            'access_token': self._access_token,
        })

        self._tokens['transaction'] = data['token']['transaction']
