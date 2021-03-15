local images = {
  kaniko: 'gcr.io/kaniko-project/executor:v1.5.1-debug@sha256:e00dfdd4a44097867c8ef671e5a7f3e31d94bd09406dbdfba8a13a63fc6b8060',
  postgres: 'postgres:12',
  python: 'python:3.9-slim-buster',
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
    POSTGRES_USER: 'postgres',
    POSTGRES_DB: 'mtls',
  },
  detach=true,
);

local test(python_version) = step(
  'test',
  'python:' + python_version + '-slim-buster',
  environment={
    POSTGRES_HOST: 'postgresql',
    COVERALLS_REPO_TOKEN: {
      from_secret: 'COVERALLS_REPO_TOKEN',
    },
  },
  commands=[
    'apt update && apt install make cmake gnupg -y',
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

local unittest_pl(pl_type, python_version, trigger={}) = pipeline(
  pl_type + ' Unit Test: ' + python_version,
  steps=[
    clone,
    postgresql,
    test(python_version),
  ],
  trigger=trigger,
);

local get_image_tag = step(
  'Get Tag',
  images.python,
  commands=[
    'apt update && apt install -y git',
    'git describe --tags > /tmp/image_tag',
  ],
  depends_on=[
    clone.name,
  ]
);

local build_with_kaniko(push=true) = step(
  'Build',
  images.kaniko,
  environment={
    [if !push then 'EXTRA_ARGS']: '--no-push',
  },
  commands=[
    |||
      /kaniko/executor \\
        --cleanup \\
        --reproducible \\
        --cache=true \\
        --cache-repo="drgrove/mtls-server_cache" \\
        --destination="drgrove/mtls-server:$$(cat /tmp/image_tag)" \\
        --image-name-with-digest-file="/tmp/mtls.digest" "$${EXTRA_ARGS}}"
    |||,
    'cat /tmp/mtls.digest',
  ],
  depends_on=[
    get_image_tag.name,
  ],
);

local image_build_pl(pl_type, trigger={}, push=false) = pipeline(
  pl_type + ' Build: Image',
  steps=[
    clone,
    get_image_tag,
    build_with_kaniko(push),
  ],
  trigger=trigger
);

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
      'refs/head/master',
    ],
  },
};

local tag_trigger = {
  event: [
    'tag',
  ],
};

[
  unittest_pl('PR', '3.9', trigger=pr_trigger),
  unittest_pl('Master', '3.9', trigger=master_trigger),
  unittest_pl('Tag', '3.9', trigger=tag_trigger),
  unittest_pl('PR', '3.8', trigger=pr_trigger),
  unittest_pl('Master', '3.8', trigger=master_trigger),
  unittest_pl('Tag', '3.8', trigger=tag_trigger),
  unittest_pl('PR', '3.7', trigger=pr_trigger),
  unittest_pl('Master', '3.7', trigger=master_trigger),
  unittest_pl('Tag', '3.7', trigger=tag_trigger),
  image_build_pl('PR', trigger=pr_trigger, push=false),
  image_build_pl('Master', trigger=master_trigger, push=false),
  image_build_pl('Tag', trigger=tag_trigger, push=true),
]
