param(
  [string]$ProjectId = "aegis-ai-guard",
  [string]$Region = "us-central1",
  [string]$ServiceName = "aegis-backend",
  [string]$ImageTag = "",
  [string]$EnvFile = "backend/cloudrun.env.yaml"
)

$ErrorActionPreference = "Stop"

if (-not $ImageTag) {
  $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
  $ImageTag = "gcr.io/$ProjectId/${ServiceName}:$timestamp"
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")

Push-Location $repoRoot
try {
  if (-not (Test-Path $EnvFile)) {
    throw "Missing env file: $EnvFile. Copy backend/cloudrun.env.yaml.example to backend/cloudrun.env.yaml and fill in secrets."
  }

  gcloud config set project $ProjectId | Out-Null

  Write-Host "Building container image $ImageTag"
  gcloud builds submit `
    --project $ProjectId `
    --config backend/cloudbuild.yaml `
    --substitutions "_IMAGE_TAG=$ImageTag" `
    .

  Write-Host "Deploying Cloud Run service $ServiceName in $Region"
  gcloud run deploy $ServiceName `
    --image $ImageTag `
    --region $Region `
    --platform managed `
    --allow-unauthenticated `
    --port 8080 `
    --cpu 2 `
    --memory 2Gi `
    --timeout 300 `
    --max-instances 10 `
    --project $ProjectId `
    --env-vars-file $EnvFile

  Write-Host ""
  Write-Host "Cloud Run deploy complete."
  Write-Host "Next: deploy Firebase Hosting so rewrites point to $ServiceName."
  Write-Host "Command: firebase deploy --only hosting"
}
finally {
  Pop-Location
}
