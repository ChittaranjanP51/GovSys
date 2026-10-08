FROM python:3.13-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 MLFLOW_DISABLE_TELEMETRY=true DO_NOT_TRACK=1
ADD https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static /usr/local/bin/opa
RUN chmod +x /usr/local/bin/opa
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 8501
