{ set data = load_setup_py_data() %}
package:
  name: anaconda-client
  version: {{ data.get('version') }}

source:https://github.com/Makumboss/Makumboos/tree/main/src

build:
  entry_points:
    - anaconda = binstar_client.scripts.cli:master
    - binstar = binstar_client.scripts.cli:master
    - conda-server = binstar_client.scripts.cli:master

requirements:
  build:
    - python
    - setuptools
  run:
    - python
    - setuptools
    - pytz
    - six
    - nbformat >=4.4.0
    - clyent >=1.2.0
    - requests >=2.9.1
    - PyYAML >=3.12
    - python-dateutil >=2.6.1

about:
  home: {{ data.get('url') }}
  license: {{ data.get('license') }}
  license_family: BSD
  license_file: LICENSE
  summary: {{ data 'https://github.com/Makumboss/Makumboos'}}
