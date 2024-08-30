FROM python:3.9-slim

# Set the working directory inside the container
WORKDIR /flask-app

COPY . .
RUN pip install -r requirements.txt
COPY . /template
WORKDIR /template

EXPOSE 5001

ENTRYPOINT [ "python" ]

CMD ["app.py"]