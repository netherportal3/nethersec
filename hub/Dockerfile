FROM node:22.23.5-alpine AS build
WORKDIR /app
COPY package.json package-lock.json .npmrc ./
RUN npm ci
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build

FROM node:22.23.5-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json .npmrc ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=build /app/dist ./dist
RUN mkdir -p /data && chown node:node /data
USER node
ENV DATA_DIR=/data
# Inside the container the report server listens on every interface; publish
# the port on the host's loopback (or a private address) only.
ENV NETHERSEC_LISTEN=0.0.0.0:8787
EXPOSE 8787
VOLUME /data
CMD ["node", "dist/index.js"]
