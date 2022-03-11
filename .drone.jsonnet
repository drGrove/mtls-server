local images = {
  curl: 'alpine/curl@sha256:c64976d53728ca1b4918a49257845af27e343c4a79090788f83afe9f3e800965',
  // https://github.com/drGrove/drone-kaniko/tree/v0.7.0
  kaniko: 'drgrove/drone-kaniko@sha256:e3045421c3683e6baf5628b22ea0ee1cd7ae217f4de0e1bc53a0a1a20335b108',
  postgres: 'postgres:12',
  python: 'python:3.9-slim-buster',
};

local pr_trigger = {
  event: [
    'pull_request',
  ],
};

local master_trigger = {
  event: [
    'push',
  ],
  ref: {
    include: [
      'refs/heads/master',
    ],
  },
};

local tag_trigger = {
  event: [
    'tag',
  ],
};

local pipeline(
  name,
  kind='pipeline',
  clone={
    disable: true,
  },
  platform=null,
  workspace=null,
  services=[],
  steps=[],
  trigger=null,
  node=null,
  volumes=[],
  depends_on=[],
      ) = {
  kind: kind,
  name: name,
  [if platform != null then 'platform']: platform,
  [if workspace != null then 'workspace']: workspace,
  [if clone != null then 'clone']: clone,
  [if services != [] then 'services']: services,
  [if steps != [] then 'steps']: steps,
  [if trigger != null then 'trigger']: trigger,
  [if node != null then 'node']: node,
  [if volumes != [] then 'volumes']: volumes,
  [if depends_on != [] then 'depends_on']: depends_on,
};


local step(
  name,
  image,
  settings=null,
  depends_on=[],
  commands=null,
  environment=null,
  failure=false,
  detach=false,
  privileged=false,
  volumes=[],
  when=null
      ) = {
  name: name,
  image: image,
  [if failure then 'failure']: 'ignore',
  [if detach then 'detach']: detach,
  [if privileged then 'privileged']: privileged,
  [if settings != null then 'settings']: settings,
  [if depends_on != [] then 'depends_on']: depends_on,
  [if commands != [] then 'commands']: commands,
  [if environment != null then 'environment']: environment,
  [if volumes != [] then 'volumes']: volumes,
  [if when != null then 'when']: when,
};

local clone = step(
  'clone',
  'plugins/git',
  settings={
    tags: true,
  },
);

local postgresql = step(
  'postgresql',
  images.postgres,
  environment={
    POSTGRES_PASSWORD: 'mtls',
    POSTGRES_DB: 'mtls',
    POSTGRES_HOST_AUTH_METHOD: 'trust',
  },
  detach=true,
);

local unittest(python_version) = step(
  'unit test',
  'python:' + python_version + '-slim-buster',
  environment={
    PGHOST: 'postgresql',
    COVERALLS_REPO_TOKEN: {
      from_secret: 'COVERALLS_REPO_TOKEN',
    },
    CLEANUP: '0',
  },
  commands=[
    'apt update && apt install -y make cmake gnupg git postgresql-client',
    'pip3 install pipenv',
    'make setup-dev',
    'cp config.ini.example config.ini',
    'make create-ca',
    'make test.dev coverage coveralls',
  ],
  depends_on=[
    clone.name,
  ]
);

local integration_test(python_version) = step(
  'integration test',
  'python:' + python_version + '-slim-buster',
  environment={
    PGHOST: 'postgresql',
    COVERALLS_REPO_TOKEN: {
      from_secret: 'COVERALLS_REPO_TOKEN',
    },
    CLEANUP: '0',
  },
  commands=[
    'apt update && apt install -y make cmake gnupg git postgresql-client',
    'pip3 install pipenv',
    'make setup-dev',
    'cp config.ini.example config.ini',
    'make create-ca',
    'make integration-test.dev coverage coveralls',
  ],
  depends_on=[
    clone.name,
  ]
);

local unittest_pl(pl_type, python_version, trigger={}) = pipeline(
  pl_type + ' Unit Test: ' + python_version,
  steps=[
    clone,
    postgresql,
    unittest(python_version),
  ],
  trigger=trigger,
);

local integration_test_pl(pl_type, python_version, trigger={}) = pipeline(
  pl_type + ' Integration Test: ' + python_version,
  steps=[
    clone,
    postgresql,
    integration_test(python_version),
  ],
  trigger=trigger,
);

local notify_coveralls_complete = step(
  'Coverage Complete',
  images.curl,
  environment={
    COVERALLS_REPO_TOKEN: {
      from_secret: 'COVERALLS_REPO_TOKEN',
    },
  },
  commands=[
    'curl -k https://coveralls.io/webhook?repo_token=$COVERALLS_REPO_TOKEN -d "payload[build_num]=$DRONE_BUILD_NUMBER&payload[status]=done"',
  ],
  depends_on=[
    clone.name,
  ],
);

local coveralls_complete_pl(pl_type, trigger={}) = pipeline(
  pl_type + ': Coverage',
  steps=[
    clone,
    notify_coveralls_complete,
  ],
  trigger=trigger,
  depends_on=[
    unittest_pl('PR', '3.10', trigger=pr_trigger).name,
    unittest_pl('Master', '3.10', trigger=master_trigger).name,
    unittest_pl('Tag', '3.10', trigger=tag_trigger).name,
    unittest_pl('PR', '3.9', trigger=pr_trigger).name,
    unittest_pl('Master', '3.9', trigger=master_trigger).name,
    unittest_pl('Tag', '3.9', trigger=tag_trigger).name,
    integration_test_pl('PR', '3.10', trigger=pr_trigger).name,
    integration_test_pl('Master', '3.10', trigger=master_trigger).name,
    integration_test_pl('Tag', '3.10', trigger=tag_trigger).name,
    integration_test_pl('PR', '3.9', trigger=pr_trigger).name,
    integration_test_pl('Master', '3.9', trigger=master_trigger).name,
    integration_test_pl('Tag', '3.9', trigger=tag_trigger).name,
  ]
);

local get_image_tag = step(
  'Get Tag',
  images.python,
  commands=[
    'apt update && apt install -y git',
    'git describe --tags > .tags',
  ],
  depends_on=[
    clone.name,
  ]
);

local build_with_kaniko(push=true) = step(
  'Build',
  images.kaniko,
  settings={
    [if push then 'repo']: 'drgrove/mtls-server',
    reproducible: true,
    username: if push then 'drgrovebot' else 'drgrovero',
    password: {
      from_secret: if push then 'drgrovebot' else 'drgrovero',
    },
  },
  depends_on=[
    if push then get_image_tag.name else clone.name,
  ],
);

local image_build_pl(pl_type, trigger={}, push=false) = pipeline(
  pl_type + ' Build: Image',
  steps=[
    clone,
  ] + if push then
    [
      get_image_tag,
      build_with_kaniko(push),
    ] else [
    build_with_kaniko(push),
  ],
  trigger=trigger
);

[
  unittest_pl('PR', '3.10', trigger=pr_trigger),
  unittest_pl('Master', '3.10', trigger=master_trigger),
  unittest_pl('Tag', '3.10', trigger=tag_trigger),
  unittest_pl('PR', '3.9', trigger=pr_trigger),
  unittest_pl('Master', '3.9', trigger=master_trigger),
  unittest_pl('Tag', '3.9', trigger=tag_trigger),
  integration_test_pl('PR', '3.10', trigger=pr_trigger),
  integration_test_pl('Master', '3.10', trigger=master_trigger),
  integration_test_pl('Tag', '3.10', trigger=tag_trigger),
  integration_test_pl('PR', '3.9', trigger=pr_trigger),
  integration_test_pl('Master', '3.9', trigger=master_trigger),
  integration_test_pl('Tag', '3.9', trigger=tag_trigger),
  coveralls_complete_pl('PR', trigger=pr_trigger),
  coveralls_complete_pl('Master', trigger=master_trigger),
  coveralls_complete_pl('Tag', trigger=tag_trigger),
  image_build_pl('PR', trigger=pr_trigger, push=false),
  image_build_pl('Master', trigger=master_trigger, push=false),
  image_build_pl('Tag', trigger=tag_trigger, push=true),
]
