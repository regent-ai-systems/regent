# deploy/

Empty on purpose. Deployment files are a Stage 1 deliverable — written the
week the first design partner signs, not before (see docs/STAGES.md).

Planned contents at Stage 1:

    deploy/docker-compose.yml        agentgateway + regent-pds + sqlite, one command
    deploy/helm/regent/              chart: pds Deployment/Service, ConfigMap for packs,
                                     Secret refs, ServiceMonitor, NetworkPolicy (deny all but gateway)
    deploy/agentgateway/config.yaml  example gateway config with extAuthz → regent-pds:9000

Until then, Stage 0 runs with `regent serve` and a local agentgateway binary,
as described in docs/install.md.
