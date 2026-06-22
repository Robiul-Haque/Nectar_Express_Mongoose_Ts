FROM public.ecr.aws/docker/library/node:20

WORKDIR /app

COPY package*.json ./

RUN npm install

COPY . .

EXPOSE 8010

CMD ["npm", "run", "dev"]