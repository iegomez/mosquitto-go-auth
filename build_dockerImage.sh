#!/bin/bash
#Build del Dockerfile
docker build -t mosquitto .

#ottieni lo short sha dell'immagine appena creata
IMAGE_SHA=$(docker inspect --format='{{.ID}}' mosquitto | cut -c8-14)



#Login al registry di github
docker login ghcr.io --username deddy2101 --password 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


#Tagga l'immagine con lo short sha
docker tag mosquitto ghcr.io/deddy2101/mosquitto-go-jwt-cloudflare:latest
docker tag mosquitto ghcr.io/deddy2101/mosquitto-go-jwt-cloudflare:$IMAGE_SHA


docker push ghcr.io/deddy2101/mosquitto-go-jwt-cloudflare:$IMAGE_SHA
docker push ghcr.io/deddy2101/mosquitto-go-jwt-cloudflare:latest

