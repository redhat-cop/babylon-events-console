# Use an official Python runtime as a parent image
FROM registry.access.redhat.com/ubi8/python-36

ENV OC_VERSION=4.2.9

WORKDIR /app
COPY requirements.txt .
RUN pip install --trusted-host pypi.python.org -r requirements.txt && \
    curl -s https://mirror.openshift.com/pub/openshift-v4/clients/ocp/${OC_VERSION}/openshift-client-linux-${OC_VERSION}.tar.gz \
    | tar zxvf - -C /opt/app-root/bin
COPY app app/

EXPOSE 8080

ENV VERSION="0.4" \
    FLASK_APP="app" \
    FLASK_ENV="development" \
    FLASK_RUN_PORT="8080" \
    FLASK_RUN_HOST="0.0.0.0"

# Run app.py when the container launches
CMD ["flask", "run"]
