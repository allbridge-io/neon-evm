## How to run tests

```bash
python3 ./.github/workflows/deploy.py build_docker_image --github_sha=1 --eof=true
python3 ./.github/workflows/deploy.py run_tests --github_sha=1 --eof=true
```
