FROM python:3.6

COPY . /
 
RUN pip install awscli --upgrade --user
RUN pip install -r requirements.txt
RUN python setup.py develop
