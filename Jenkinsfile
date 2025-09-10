pipeline {
    agent any
    environment {
        IMAGE_NAME = "tpvapi/auth-system:v1.0.1"
        DOCKERHUB_CREDENTIALS = credentials('d96c59d5-f766-4100-a32e-81b4a5e52653') // Jenkins credentials ID
    }
    stages {
        stage('Checkout') {
            steps {
                git branch: 'main', url: 'https://github.com/ajay-turningpoint-vapi/microservices.git'
            }
        }
        stage('Build Docker Image') {
            steps {
                script {
                    def TAG = sh(script: "git rev-parse --short HEAD", returnStdout: true).trim()
                    sh "docker build -t ${IMAGE_NAME}:${TAG} ."
                }
            }
        }
        stage('Push to Docker Hub') {
            steps {
                script {
                    def TAG = sh(script: "git rev-parse --short HEAD", returnStdout: true).trim()
                    sh "echo ${DOCKERHUB_CREDENTIALS_PSW} | docker login -u ${DOCKERHUB_CREDENTIALS_USR} --password-stdin"
                    sh "docker push ${IMAGE_NAME}:${TAG}"
                }
            }
        }
    }
}
