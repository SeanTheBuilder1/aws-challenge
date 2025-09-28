FROM node:22-slim
COPY --from=public.ecr.aws/awsguru/aws-lambda-adapter:0.9.1 /lambda-adapter /opt/extensions/lambda-adapter
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
ENV PORT=8080
EXPOSE 8080
ENV NODE_ENV=production
CMD ["npm", "run", "start"]
