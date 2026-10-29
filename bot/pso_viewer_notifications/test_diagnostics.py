import contextlib
import io
import unittest
from unittest.mock import Mock, patch

import pso_viewer
from team_publish import TeamFailure


class RecipientDiagnosticsTests(unittest.TestCase):
    def inspect(self, outcomes, state=None):
        team = Mock()
        team.status.return_value = state or {'state': 'active', 'role': 'bot'}
        team.recipients.side_effect = outcomes
        identity = Mock()
        identity.run.return_value = b'OpenSSL test'
        output = io.StringIO()
        with patch.object(pso_viewer, 'OpenSSLIdentity', return_value=identity), \
                patch.object(pso_viewer, 'TeamClient', return_value=team), \
                contextlib.redirect_stdout(output):
            pso_viewer.encryption_status()
        return output.getvalue(), team

    def test_missing_cardio_still_checks_intensivists_without_sending(self):
        output, team = self.inspect([
            TeamFailure('blocked', 'No cardiologist', 'no_recipients'),
            [{'id': 'intensivist-1'}],
        ])
        self.assertIn('Кардиолог: активных получателей 0.', output)
        self.assertIn('Реаниматологи: активных получателей 1', output)
        self.assertEqual([call[0][0] for call in team.recipients.call_args_list], ['cardio', 'orit'])
        self.assertEqual([call[0] for call in team.mock_calls], ['status', 'recipients', 'recipients'])

    def test_missing_intensivists_does_not_hide_present_cardio(self):
        output, _ = self.inspect([
            [{'id': 'cardiologist-1'}],
            TeamFailure('blocked', 'No intensivist', 'no_recipients'),
        ])
        self.assertIn('Кардиолог: активных получателей 1', output)
        self.assertIn('Реаниматологи: активных получателей 0.', output)

    def test_global_errors_are_not_reported_as_empty_group(self):
        for error in [TeamFailure('retry', 'Network error'),
                      TeamFailure('blocked', 'Unverified recipient'),
                      TeamFailure('retry', 'Rate limit', 'no_recipients')]:
            with self.subTest(kind=error.kind, code=error.code):
                with self.assertRaises(TeamFailure):
                    self.inspect([error])

    def test_inactive_or_wrong_role_bot_does_not_check_recipients(self):
        for state in [{'state': 'pending'}, {'state': 'active', 'role': 'neurologist'}]:
            with self.subTest(state=state):
                _, team = self.inspect([], state)
                team.recipients.assert_not_called()


if __name__ == '__main__':
    unittest.main()
