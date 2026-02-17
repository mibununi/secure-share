# build stage
FROM node:18-alpine AS build
WORKDIR /usr/src/app

COPY package*.json ./
RUN npm install

COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# runtime stage
FROM node:18-alpine
WORKDIR /usr/src/app

COPY package*.json ./
RUN npm install --omit=dev

COPY --from=build /usr/src/app/dist ./dist

ENV CHAINCODE_SERVER_ADDRESS=0.0.0.0:9999
EXPOSE 9999

CMD ["npm", "start"]