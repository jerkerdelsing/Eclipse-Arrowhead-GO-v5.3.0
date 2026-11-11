# Prebuilt static binary (make image cross-compiles it into bin/linux/); no shell, non-root, read-only friendly.
FROM scratch
COPY bin/linux/localcloudconfigurator /localcloudconfigurator
COPY catalogs /catalogs
USER 65532:65532
EXPOSE 8095
ENTRYPOINT ["/localcloudconfigurator"]
CMD ["serve", "-listen", ":8095", "-catalog", "/catalogs/gocloud.json"]
