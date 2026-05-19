Execute on devicee for enhanced HTTPS browsing

Recommended via Termux
```bash
proot-distro install debian
proot-distro login debian
```

```bash
mkdir -p ~/.deadlight

openssl genrsa -out ~/.deadlight/ca.key 4096
openssl req -new -x509 -days 3650 \
  -key ~/.deadlight/ca.key \
  -out ~/.deadlight/ca.crt \
  -subj "/CN=deadlight CA/O=deadlight/C=US"

chmod 600 ~/.deadlight/ca.key
chmod 644 ~/.deadlight/ca.crt
Install it system-wide so curl and other tools trust it:

cp ~/.deadlight/ca.crt /usr/local/share/ca-certificates/deadlight.crt
update-ca-certificates
```
