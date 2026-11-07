/** PA-690 manual read-only effective protected configuration shape check. */
import {verifyCustodyConfiguration} from './create-once.mjs';
try {
  verifyCustodyConfiguration({
    repo:process.env.GITHUB_REPOSITORY,actor:process.env.GITHUB_ACTOR,
    ref:process.env.GITHUB_REF,sha:process.env.GITHUB_SHA,
    runAttempt:Number(process.env.GITHUB_RUN_ATTEMPT),
    action:process.env.CUSTODY_ACTION,
    approvedSha:process.env.APPROVED_COMMIT_SHA,
    account:process.env.CF_TARGET_ACCOUNT,
    store:process.env.CF_TARGET_STORE,
    secretName:process.env.CF_TARGET_SECRET_NAME,
    requireToken:false,
  });
  process.stdout.write('PA690_CONFIG_SHAPE_PASS_MANUAL_TARGET_VERIFICATION_REQUIRED_NO_CLOUD_AUTHORITY\n');
} catch(error) {
  const safe = new Set(['CONFIG_CONTEXT','CONFIG_COMMIT','CONFIG_ACCOUNT',
    'CONFIG_STORE','CONFIG_SECRET_NAME']);
  const stage = safe.has(error?.stage) ? error.stage : 'UNCLASSIFIED';
  process.stderr.write('HOLD_PA690_CONFIG_NOT_VERIFIED stage=' + stage + '\n');
  process.exitCode=1;
}
