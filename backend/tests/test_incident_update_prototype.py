import unittest

from fastapi import HTTPException

from backend.app.main import INCIDENTS, update_incident_status


class IncidentUpdatePrototypeTests(unittest.TestCase):
    def test_incident_updates_are_disabled_without_auth(self):
        original_status = INCIDENTS["INC-001"]["status"]

        with self.assertRaises(HTTPException) as error:
            update_incident_status("INC-001")

        self.assertEqual(error.exception.status_code, 503)
        self.assertEqual(INCIDENTS["INC-001"]["status"], original_status)

    def test_missing_incident_still_returns_not_found(self):
        with self.assertRaises(HTTPException) as error:
            update_incident_status("missing-incident")

        self.assertEqual(error.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
