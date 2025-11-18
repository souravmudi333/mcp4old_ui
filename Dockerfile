FROM python:3.11-alpine

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apk add --no-cache gcc musl-dev libffi-dev

COPY requirements.txt /app/

RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/

EXPOSE 8045

CMD ["uvicorn", "mcpgateway.main:app", "--host", "0.0.0.0", "--port", "8045"]


# docker build -t fastapi-sample .
# docker run -p 8045:8045 fastapi-sample