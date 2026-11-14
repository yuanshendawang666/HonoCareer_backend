import uuid

from tests.conftest import account


def _account_with_two_sessions(client):
    body = {'account': uuid.uuid4().hex, 'password': 'Safe-test-password-123', 'nickname': '测试同学'}
    assert client.post('/api/v1/auth/register', json=body).status_code == 200

    def login():
        payload = {'account': body['account'], 'password': body['password'], 'clientType': 'web'}
        response = client.post('/api/v1/auth/login', json=payload)
        assert response.status_code == 200, response.text
        tokens = response.json()['data']
        return {'Authorization': 'Bearer ' + tokens['accessToken']}, tokens

    return body, login(), login()


def test_change_password_revokes_all_sessions_and_requires_new(client):
    body, first, second = _account_with_two_sessions(client)
    auth1, _ = first
    auth2, _ = second
    new_password = 'New-safe-password-456'

    response = client.post('/api/v1/auth/change-password', headers=auth1,
                           json={'oldPassword': 'wrong', 'newPassword': new_password})
    assert response.status_code == 400 and response.json()['code'] == 'OLD_PASSWORD_WRONG'

    response = client.post('/api/v1/auth/change-password', headers=auth1,
                           json={'oldPassword': body['password'], 'newPassword': body['password']})
    assert response.status_code == 400 and response.json()['code'] == 'PASSWORD_UNCHANGED'

    assert client.post('/api/v1/auth/change-password', headers=auth1,
                       json={'oldPassword': body['password'], 'newPassword': new_password}).status_code == 200

    # 所有设备的会话被撤销
    assert client.get('/api/v1/users/me', headers=auth1).status_code == 401
    assert client.get('/api/v1/users/me', headers=auth2).status_code == 401

    # 旧密码失效，新密码可登录
    response = client.post('/api/v1/auth/login', json={'account': body['account'], 'password': body['password'], 'clientType': 'web'})
    assert response.status_code == 401 and response.json()['code'] == 'AUTH_INVALID_CREDENTIALS'
    response = client.post('/api/v1/auth/login', json={'account': body['account'], 'password': new_password, 'clientType': 'web'})
    assert response.status_code == 200


def test_change_password_requires_auth_and_validates(client):
    assert client.post('/api/v1/auth/change-password',
                       json={'oldPassword': 'x', 'newPassword': 'Safe-new-password-1'}).status_code == 401

    _, tokens = account(client)
    headers = {'Authorization': 'Bearer ' + tokens['accessToken']}
    response = client.post('/api/v1/auth/change-password', headers=headers,
                           json={'oldPassword': 'x', 'newPassword': 'short'})
    assert response.status_code == 400 and response.json()['code'] == 'VALIDATION_ERROR'
