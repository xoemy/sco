FROM alpine

WORKDIR /
ENV TZ="Asia/Shanghai" 

ADD cc nm web start.sh ./

RUN apk add --no-cache iproute2 vim netcat-openbsd &&\
    chmod -v 755 start.sh &&\
    addgroup --gid 10001 jx &&\
    adduser --disabled-password  --no-create-home --uid 10001 --ingroup jx jxuser

ENTRYPOINT [ "./start.sh" ]

EXPOSE 3000

USER 10001
