FROM python:3.11

COPY . /

RUN pip install awscli --upgrade --user
RUN pip install boto3 lxml requests
RUN python setup.py develop
