# Use an official Python runtime as a parent image
FROM registry.access.redhat.com/ubi8/python-36

WORKDIR /app
COPY requirements.txt .
RUN pip install --trusted-host pypi.python.org -r requirements.txt
COPY app app/

EXPOSE 8080

ENV VERSION "0.4"
ENV FLASK_APP "app"
ENV FLASK_ENV "development"
ENV FLASK_RUN_PORT "8080"
ENV FLASK_RUN_HOST "0.0.0.0"

# Run app.py when the container launches
CMD ["flask", "run"]
