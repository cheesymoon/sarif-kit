# Image behind the GitHub Action, so Action users never install Python or the
# package themselves. Built and pushed to GHCR by .github/workflows/publish-image.yml;
# action.yml pins the tag it runs.
FROM python:3.13-slim

LABEL org.opencontainers.image.source="https://github.com/sarif-kit/sarif-kit"
LABEL org.opencontainers.image.description="Convert native scanner output into SARIF 2.1.0 for GitHub Code Scanning"
LABEL org.opencontainers.image.licenses="Apache-2.0"

COPY . /src
RUN pip install --no-cache-dir /src && rm -rf /src

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
