FROM python:3.13-slim

# 只装运行时需要的东西：Pillow 的 wheel 自带编解码库，不需要额外 apt 包
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    RVCAMP_DEV=0 \
    RVCAMP_DATA=/data

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY frontend/ ./frontend/

# 不用 root 跑服务：容器被突破时攻击者拿不到宿主机 root
RUN useradd -m -u 10001 rv \
 && mkdir -p /data/uploads /data/logs /data/backups \
 && chown -R rv:rv /data
USER rv

EXPOSE 8000

# 健康检查：/api/meta 不查库，适合做探活
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/meta').status==200 else 1)"

CMD ["python", "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "backend"]
