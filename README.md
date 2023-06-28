
# Create Cloud Run Service

gcloud services enable \
    compute.googleapis.com \
    run.googleapis.com \
    aiplatform.googleapis.com \
    artifactregistry.googleapis.com \
    containerregistry.googleapis.com

gcloud init

PROJECT=$(gcloud config get project)

REGION=us-central1

gcloud auth configure-docker

gsutil cp gs://jkr-public/cr.tar .

docker load < cr.tar

# Create service account
gcloud iam service-accounts create cloud-run-llm \
    --description="Service account to call LLM models from Cloud Run" \
    --display-name="cloud-run-llm"

# add aiplatform.user role
gcloud projects add-iam-policy-binding $PROJECT \
    --member="serviceAccount:cloud-run-llm@$PROJECT.iam.gserviceaccount.com" \
    --role="roles/aiplatform.user"

# add logging.logWriter role
gcloud projects add-iam-policy-binding $PROJECT \
    --member="serviceAccount:cloud-run-llm@$PROJECT.iam.gserviceaccount.com" \
    --role="roles/logging.logWriter"

# add permission to impersonate the sa (iam.serviceAccounts.actAs), since this is a user-namaged sa
gcloud iam service-accounts add-iam-policy-binding \
    cloud-run-llm@$PROJECT.iam.gserviceaccount.com \
    --member="user:$USER_EMAIL" \
    --role="roles/iam.serviceAccountUser"

###
docker image tag \
    gcr.io/manifest-emblem-651/cloud-run-microservice-template-python:latest \
    gcr.io/$PROJECT/genai-ad:latest

docker push gcr.io/$PROJECT/genai-ad

gcloud run deploy genai-ad \
    --project=$PROJECT \
    --platform=managed \
    --region=$REGION \
    --ingress=internal-and-cloud-load-balancing \
    --port=7860 \
    --no-allow-unauthenticated \
    --image=gcr.io/$PROJECT/genai-ad


# Enable IAP for Cloud Run Services
# Set up Shell Variables

SERVICE_NAME="genai-ad"

REGION="us-central1"
PROJECT_ID=$(gcloud config get-value project)
echo PROJECT_ID=$PROJECT_ID

# project number
PROJECT_NUMBER=$(gcloud projects describe ${PROJECT_ID} --format="value(project_number)")

BASE_DOMAIN="endpoints.${PROJECT_ID}.cloud.goog"
FQDN="${SERVICE_NAME}.${BASE_DOMAIN}"
#BRAND_TITLE=${SERVICE_NAME}
BRAND_TITLE="run"

# IAP settings

# this is a support email needed by IAP setup
SUPPORT_EMAIL="$(gcloud config get-value account)"

# Domain name for Google-managed certificates has to be <= 63 characters
# This length limit only applies to Google-managed SSL certificates. In those certificates, the 64-byte limit only applies to the first domain in the certificate. The length limit for the other domains in the certificate is 253 (which applies to any domain name on the internet, and isn't specific to Google-managed certificates.
# To avoid hitting this limit, this guide always tries to set up a shorter domain
CERT_DOMAIN="cert.$BASE_DOMAIN"
echo CERT_DOMAIN="$CERT_DOMAIN"
if [ ${#CERT_DOMAIN} -gt 64 ]; then echo "The CERT_BASE_DOMAIN must be no longer than 64 characters. https://cloud.google.com/load-balancing/docs/quotas#ssl_certificates"; fi

echo FQDN="$FQDN"
if [ ${#FQDN} -gt 253 ]; then echo "The FQDN must be no longer than 253 characters. https://cloud.google.com/load-balancing/docs/quotas#ssl_certificates"; fi
# Prepare Project APIs and Org Policies
gcloud services enable compute.googleapis.com iap.googleapis.com cloudresourcemanager.googleapis.com
# Configure OAuth for IAP
# Retrieve the OAuth brand
BRAND_NAME=$(gcloud iap oauth-brands list --format='value(name)')

# Create if it doesn't exist
if [ -z "$BRAND_NAME" ]
then
    # Create brand. support_email is required (it can be a group address)
    # This command provisions the brand as orgInternalOnly: true
    gcloud iap oauth-brands create --application_title=${BRAND_TITLE} \
        --support_email=${SUPPORT_EMAIL}
    BRAND_NAME=$(gcloud iap oauth-brands list --format='value(name)')
fi

OAUTH_CLIENT=$(gcloud iap oauth-clients list ${BRAND_NAME} --filter='displayName=("'$BRAND_NAME'")' --format='value(name)')
if [ -z "$OAUTH_CLIENT" ]
then
  gcloud iap oauth-clients create ${BRAND_NAME} --display_name=${BRAND_NAME}
fi

# Retrieve the OAuth Client ID/Secret just to make sure they are working
read -r OAUTH_CLIENT_ID OAUTH_CLIENT_SECRET < <(gcloud iap oauth-clients list ${BRAND_NAME} --filter='displayName=("'$BRAND_NAME'")' --format='value(name,secret)')
OAUTH_CLIENT_ID=$(echo $OAUTH_CLIENT_ID | sed 's/.*\///' )

echo OAUTH_CLIENT_ID=$OAUTH_CLIENT_ID
echo OAUTH_CLIENT_SECRET=$OAUTH_CLIENT_SECRET
# Set up Cloud Run Invoker Permission
# Use this for testing with a sample Cloud Run
#gcloud run deploy "${SERVICE_NAME}" --platform=managed --region=${REGION} --image="us-docker.pkg.dev/cloudrun/container/hello" --memory=512Mi --ingress=internal-and-cloud-load-balancing --no-allow-unauthenticated

IAP_SERVICE_AGENT=$(gcloud beta services identity create --service=iap.googleapis.com --format="value(email)")
echo IAP_SERVICE_AGENT=$IAP_SERVICE_AGENT
# Option - grant IAM permission on an existing Cloud Run Service
gcloud run services add-iam-policy-binding $SERVICE_NAME --region=${REGION} --member="serviceAccount:${IAP_SERVICE_AGENT}" --role="roles/run.invoker"
# Option - grant IAM permission on the project level
# gcloud projects add-iam-policy-binding $PROJECT_ID --member="serviceAccount:${IAP_SERVICE_AGENT}" --role="roles/run.invoker"

gcloud compute addresses create ${SERVICE_NAME}-ip --global

#IP_ADDRESS=$(gcloud compute forwarding-rules describe ${SERVICE_NAME}-https-forwardingrule  --global --format='value(IPAddress)')
IP_ADDRESS=$(gcloud compute addresses describe ${SERVICE_NAME}-ip --global --format="value(address)")

echo IP_ADDRESS=$IP_ADDRESS


# Cloud Endpoints approach - Map the FQDN to the IP address
for DOMAIN in cert.${BASE_DOMAIN} $FQDN
do
  ENDPOINTS_SERVICE=$(echo "$DOMAIN" | cut -d"." -f1)

  cat <<EOF > ${ENDPOINTS_SERVICE}-openapi.yaml
swagger: "2.0"
info:
  description: "${ENDPOINTS_SERVICE}"
  title: "${ENDPOINTS_SERVICE}"
  version: "1.0.0"
host: "${DOMAIN}"
x-google-endpoints:
- name: "${DOMAIN}"
  target: "$IP_ADDRESS"
paths: {}
EOF

  gcloud endpoints services deploy ${ENDPOINTS_SERVICE}-openapi.yaml
  rm ${ENDPOINTS_SERVICE}-openapi.yaml

done

# then handle the certificates (because it takes time)
gcloud compute ssl-certificates create "${SERVICE_NAME}-ssl-cert" --domains "${CERT_DOMAIN},${FQDN}"
# gcloud compute ssl-certificates list

gcloud compute network-endpoint-groups create "${SERVICE_NAME}-neg" \
    --region="${REGION}" \
    --network-endpoint-type=serverless  \
    --cloud-run-url-mask="<service>.${BASE_DOMAIN}"
    #--cloud-run-service="${SERVICE_NAME}"


# port-name has to be called "http" even though it is HTTPS
gcloud compute backend-services create ${SERVICE_NAME}-backend --global --protocol=HTTPS --port-name="http" --load-balancing-scheme=EXTERNAL_MANAGED  --iap=enabled,oauth2-client-id=${OAUTH_CLIENT_ID},oauth2-client-secret=${OAUTH_CLIENT_SECRET} 

# Allow the current user to get access via IAP
gcloud iap web add-iam-policy-binding --member="user:$(gcloud config get-value account)" --role="roles/iap.httpsResourceAccessor" --resource-type=backend-services --service="${SERVICE_NAME}-backend"

gcloud compute backend-services add-backend "${SERVICE_NAME}-backend" \
    --global \
    --network-endpoint-group="${SERVICE_NAME}-neg" \
    --network-endpoint-group-region="${REGION}"

# Set up the URL map
gcloud compute url-maps create "${SERVICE_NAME}-https-load-balancer" --default-service="${SERVICE_NAME}-backend"

gcloud compute target-https-proxies create "${SERVICE_NAME}-httpsproxy" \
    --url-map="${SERVICE_NAME}-https-load-balancer" \
    --ssl-certificates="${SERVICE_NAME}-ssl-cert" 

# to update a cert
# gcloud compute target-https-proxies update "${SERVICE_NAME}-httpsproxy" --ssl-certificates="${SERVICE_NAME}-ssl-cert" 

gcloud compute forwarding-rules create ${SERVICE_NAME}-https-forwardingrule \
    --load-balancing-scheme=EXTERNAL_MANAGED \
    --network-tier=PREMIUM \
    --target-https-proxy=${SERVICE_NAME}-httpsproxy \
    --global --ports=443 \
    --address=${SERVICE_NAME}-ip

## http-to-https redirect

cat  <<EOF | gcloud compute url-maps import "${SERVICE_NAME}-http-load-balancer" --global --source=-
kind: compute#urlMap
name: ${SERVICE_NAME}-http-load-balancer
defaultUrlRedirect:
  redirectResponseCode: MOVED_PERMANENTLY_DEFAULT
  httpsRedirect: True
EOF

gcloud compute target-http-proxies create "${SERVICE_NAME}-httpproxy" --url-map="${SERVICE_NAME}-http-load-balancer"

gcloud compute forwarding-rules create ${SERVICE_NAME}-http-forwardingrule \
    --load-balancing-scheme=EXTERNAL_MANAGED \
    --network-tier=PREMIUM \
    --target-http-proxy=${SERVICE_NAME}-httpproxy \
    --global --ports=80 --address=${SERVICE_NAME}-ip

printf "\n\n\nThe URL will be https://${FQDN} \n\n\n"

gsutil cp gs://jkr-public/genai.tar .
tar xvf genai.tar

Edit app.py and change project ID

pip install virtualenv
virtualenv genai-pip
source genai-pip/bin/activate
genai-pip/bin/pip install google-cloud-aiplatform
gcloud builds submit --tag \
    gcr.io/$(gcloud config get project)/genai:latest .

Docker build –load genai
