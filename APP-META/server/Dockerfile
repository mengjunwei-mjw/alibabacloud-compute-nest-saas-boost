FROM node:latest AS frontend-builder

WORKDIR /root/workspace

ADD . /root/workspace

WORKDIR /root/workspace/alibabacloud-compute-nest-saas-boost/boost.front

RUN npm install -g npm@10.2.4

RUN npm run build

FROM maven:3.6.3 AS backend-builder

WORKDIR /workspace

COPY --from=frontend-builder /workspace/boost.front/dist /workspace/boost.server/src/main/resources/static

RUN mvn clean package -pl '!boost.serverless' -DskipTests

FROM openjdk:8-jdk

WORKDIR /app

COPY --from=backend-builder /workspace/boost.server/target/boost.server-1.0.0-SNAPSHOT.jar .

EXPOSE 9999

# 指定容器启动执行命令
CMD ["java", "-jar", "boost.server-1.0.0-SNAPSHOT.jar"]
