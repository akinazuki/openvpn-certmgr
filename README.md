```
docker build . -t certmgr

docker run -v YOUR_PKI_FILES_PATH:/pki certmgr --help # help

docker run -v YOUR_PKI_FILES_PATH:/pki certmgr --list-issued # list all issued certificates

docker run -v YOUR_PKI_FILES_PATH:/pki certmgr --list-revoked # list all revoked certificates

docker run -v YOUR_PKI_FILES_PATH:/pki certmgr --issue --name test@test.moe --days 365 # issue a certificate for a specific name with expiration of 365 days

docker run -v YOUR_PKI_FILES_PATH:/pki certmgr --revoke --name # revoke a certificate for a specific name

docker run -v YOUR_PKI_FILES_PATH:/pki certmgr --generate-openvpn-config --name test@test.moe # generate an openvpn config for a specific name (output to stdout)

```