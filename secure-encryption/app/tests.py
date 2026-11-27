"""Container integration tests which do not make AWS calls."""
import unittest
from unittest.mock import patch
from wsgi import app


class ApplicationTests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True)
        self.client = app.test_client()

    def test_health(self):
        response = self.client.get('/api/health')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {'status': 'ok'})

    def test_frontend_and_assets(self):
        with self.client.get('/') as response:
            self.assertIn(b'Secure S3 Encryptor', response.data)
        with self.client.get('/styles.css') as response:
            self.assertEqual(response.status_code, 200)
        self.assertIn(b'window.location.origin', self.client.get('/app.js').data)
        self.assertNotIn(b'http://localhost:5000', self.client.get('/app.js').data)

    def test_missing_credentials_rejected_without_aws_call(self):
        with patch('app.ops.make_session') as make_session:
            response = self.client.post('/api/validate', json={})
            self.assertEqual(response.status_code, 400)
            self.assertFalse(response.json['success'])
            make_session.assert_not_called()

    def test_cross_origin_post_rejected(self):
        response = self.client.post('/api/apply', json={}, headers={'Origin': 'https://untrusted.example'})
        self.assertEqual(response.status_code, 403)

    def test_static_path_traversal_not_served(self):
        response = self.client.get('/../../requirements.lock')
        self.assertEqual(response.status_code, 404)

    def test_same_origin_validation_path(self):
        with patch('app.ops.make_session') as make_session, patch('app.ops.validate_identity') as identity:
            identity.return_value = {'account': '000000000000', 'arn': 'test-only-mocked-identity'}
            response = self.client.post('/api/validate', json={
                'accessKeyId': 'test-key', 'secretAccessKey': 'test-secret', 'region': 'ap-south-1'},
                headers={'Origin': 'http://localhost'})
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.json['success'])
            make_session.assert_called_once()


if __name__ == '__main__':
    unittest.main(verbosity=2)
