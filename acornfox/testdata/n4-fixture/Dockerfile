FROM python:3.12-alpine3.23
COPY wheels /wheels
RUN pip install --no-index --find-links=/wheels pg8000==1.31.2 PyMySQL==1.1.1 redis==5.2.1 && rm -rf /wheels
WORKDIR /app
COPY app.py /app/app.py
VOLUME /data
EXPOSE 8000
CMD ["python", "-u", "/app/app.py"]
