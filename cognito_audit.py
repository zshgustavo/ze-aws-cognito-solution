"""
Exemplo:
    python cognito_audit.py \
      --region us-west-2 \
      --user-pool-id us-west-2_XXXXXXXXX \
      --client-id 5nf4hu2emee1psus7a5ognmfrj \
      --expected-redirect-uri https://app.exemplo.com/callback \
      --expected-logout-uri https://app.exemplo.com/logout \
      --domain ze-auth-service-consumer-prod.auth.us-west-2.amazoncognito.com \
      --probe-hosted-ui \
      --format markdown
"""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple  # noqa: F401

try:
    import boto3
    from botocore.exceptions import (
        BotoCoreError,
        ClientError,
        NoCredentialsError,
        ProfileNotFound,
    )
except ImportError:  # pragma: no cover
    boto3 = None
    BotoCoreError = ClientError = NoCredentialsError = ProfileNotFound = Exception


@dataclass
class CheckResult:
    id: str
    severity: str
    status: str
    message: str
    recommendation: str


@dataclass
class ProbeResult:
    authorize_url: str
    http_status: Optional[int]
    location: Optional[str]
    error: Optional[str]
    raw_exception: Optional[str]


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def normalize_uri(uri: str) -> str:
    """Return a decoded, stripped URI for exact-match comparison diagnostics."""
    return urllib.parse.unquote(uri.strip())


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audita um app client do Amazon Cognito para diagnosticar redirect_mismatch.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            Observações:
              - O script não altera nenhuma configuração no AWS Cognito; ele apenas lê e valida.
              - As credenciais AWS devem estar configuradas via AWS_PROFILE, variáveis de ambiente,
                SSO, role da instância, ou outro provider padrão do boto3.
              - Para validar redirect_mismatch, informe pelo menos --expected-redirect-uri.
            """
        ),
    )
    parser.add_argument(
        "--region",
        required=True,
        help="Região AWS do User Pool, por exemplo us-west-2.",
    )
    parser.add_argument(
        "--user-pool-id",
        required=True,
        help="ID do User Pool, por exemplo us-west-2_XXXXXXXXX.",
    )
    parser.add_argument("--client-id", required=True, help="App Client ID do Cognito.")
    parser.add_argument(
        "--expected-redirect-uri",
        action="append",
        default=[],
        help="Callback URI esperada. Pode ser usada múltiplas vezes.",
    )
    parser.add_argument(
        "--expected-logout-uri",
        action="append",
        default=[],
        help="Logout URI esperada. Pode ser usada múltiplas vezes.",
    )
    parser.add_argument(
        "--domain",
        help="Domínio do Hosted UI, com ou sem https://. Ex.: ze-auth-service-consumer-prod.auth.us-west-2.amazoncognito.com",
    )
    parser.add_argument(
        "--response-type",
        default="code",
        choices=["code", "token"],
        help="response_type esperado no fluxo OAuth. Padrão: code.",
    )
    parser.add_argument(
        "--scope",
        default="openid",
        help="Scopes a usar no probe do Hosted UI. Padrão: openid.",
    )
    parser.add_argument(
        "--probe-hosted-ui",
        action="store_true",
        help="Faz uma chamada segura ao /oauth2/authorize e captura o redirect/erro sem autenticar.",
    )
    parser.add_argument("--profile", help="Nome do perfil AWS local, se aplicável.")
    parser.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="Formato da saída. Padrão: markdown.",
    )
    parser.add_argument("--output", help="Caminho opcional para salvar o relatório.")
    return parser.parse_args()


def boto3_client(region: str, profile: Optional[str]) -> Any:
    if boto3 is None:
        print(
            "ERRO: boto3 não está instalado. Execute: pip install boto3",
            file=sys.stderr,
        )
        sys.exit(2)
    try:
        if profile:
            session = boto3.Session(profile_name=profile, region_name=region)
        else:
            session = boto3.Session(region_name=region)
        return session.client("cognito-idp")
    except ProfileNotFound as exc:
        print(f"ERRO: perfil AWS não encontrado: {exc}", file=sys.stderr)
        sys.exit(2)


def describe_client(cognito: Any, user_pool_id: str, client_id: str) -> Dict[str, Any]:
    try:
        response = cognito.describe_user_pool_client(
            UserPoolId=user_pool_id, ClientId=client_id
        )
        return response["UserPoolClient"]
    except NoCredentialsError:
        print(
            "ERRO: credenciais AWS não encontradas. Configure AWS_PROFILE, AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, SSO ou role.",
            file=sys.stderr,
        )
        sys.exit(2)
    except ClientError as exc:
        print(f"ERRO AWS ao consultar app client: {exc}", file=sys.stderr)
        sys.exit(2)
    except BotoCoreError as exc:
        print(f"ERRO boto3 ao consultar app client: {exc}", file=sys.stderr)
        sys.exit(2)


def add_check(
    checks: List[CheckResult],
    id_: str,
    severity: str,
    status: str,
    message: str,
    recommendation: str,
) -> None:
    checks.append(
        CheckResult(
            id=id_,
            severity=severity,
            status=status,
            message=message,
            recommendation=recommendation,
        )
    )


def validate_client_config(
    client: Dict[str, Any], args: argparse.Namespace
) -> List[CheckResult]:
    checks: List[CheckResult] = []
    callback_urls = [normalize_uri(x) for x in client.get("CallbackURLs", [])]
    logout_urls = [normalize_uri(x) for x in client.get("LogoutURLs", [])]
    expected_redirects = [normalize_uri(x) for x in args.expected_redirect_uri]
    expected_logouts = [normalize_uri(x) for x in args.expected_logout_uri]
    default_redirect = (
        normalize_uri(client.get("DefaultRedirectURI", ""))
        if client.get("DefaultRedirectURI")
        else None
    )
    allowed_flows = client.get("AllowedOAuthFlows", []) or []
    allowed_scopes = client.get("AllowedOAuthScopes", []) or []
    oauth_enabled = bool(client.get("AllowedOAuthFlowsUserPoolClient", False))
    supported_idps = client.get("SupportedIdentityProviders", []) or []

    if oauth_enabled:
        add_check(
            checks,
            "oauth-enabled",
            "INFO",
            "PASS",
            "Recursos OAuth do app client estão habilitados.",
            "Nenhuma ação necessária para este item.",
        )
    else:
        add_check(
            checks,
            "oauth-enabled",
            "CRITICAL",
            "FAIL",
            "AllowedOAuthFlowsUserPoolClient está desabilitado.",
            "Habilite os recursos OAuth/Hosted UI no app client antes de usar /oauth2/authorize.",
        )

    if callback_urls:
        add_check(
            checks,
            "callback-urls-present",
            "INFO",
            "PASS",
            f"Foram encontradas {len(callback_urls)} callback URL(s) cadastradas.",
            "Confirme se a aplicação usa exatamente uma dessas URLs no parâmetro redirect_uri.",
        )
    else:
        add_check(
            checks,
            "callback-urls-present",
            "CRITICAL",
            "FAIL",
            "Nenhuma CallbackURL está cadastrada no app client.",
            "Cadastre pelo menos uma Allowed callback URL no app client.",
        )

    if expected_redirects:
        for uri in expected_redirects:
            if uri in callback_urls:
                add_check(
                    checks,
                    f"expected-redirect:{uri}",
                    "INFO",
                    "PASS",
                    f"A redirect_uri esperada está cadastrada: {uri}",
                    "Nenhuma ação necessária para este item.",
                )
            else:
                near = find_near_matches(uri, callback_urls)
                detail = f"A redirect_uri esperada NÃO está cadastrada: {uri}"
                if near:
                    detail += f". Possíveis URLs parecidas: {', '.join(near)}"
                add_check(
                    checks,
                    f"expected-redirect:{uri}",
                    "CRITICAL",
                    "FAIL",
                    detail,
                    "Adicione essa URL exata em CallbackURLs ou corrija a aplicação para enviar uma URL já cadastrada.",
                )
    else:
        add_check(
            checks,
            "expected-redirect-not-provided",
            "MEDIUM",
            "WARN",
            "Nenhuma --expected-redirect-uri foi informada; não é possível confirmar a URL real da aplicação.",
            "Execute novamente informando a redirect_uri gerada pela aplicação.",
        )

    if default_redirect:
        if default_redirect in callback_urls:
            add_check(
                checks,
                "default-redirect",
                "INFO",
                "PASS",
                f"DefaultRedirectURI está cadastrada em CallbackURLs: {default_redirect}",
                "Nenhuma ação necessária para este item.",
            )
        else:
            add_check(
                checks,
                "default-redirect",
                "HIGH",
                "FAIL",
                f"DefaultRedirectURI não está presente em CallbackURLs: {default_redirect}",
                "Inclua a DefaultRedirectURI também em CallbackURLs ou ajuste/remova o valor padrão.",
            )
    else:
        add_check(
            checks,
            "default-redirect",
            "LOW",
            "INFO",
            "Nenhuma DefaultRedirectURI configurada.",
            "Isso é aceitável se a aplicação sempre envia redirect_uri explicitamente.",
        )

    if args.response_type in allowed_flows:
        add_check(
            checks,
            "oauth-flow",
            "INFO",
            "PASS",
            f"O fluxo OAuth '{args.response_type}' está permitido.",
            "Nenhuma ação necessária para este item.",
        )
    else:
        add_check(
            checks,
            "oauth-flow",
            "HIGH",
            "FAIL",
            f"O fluxo OAuth '{args.response_type}' não aparece em AllowedOAuthFlows: {allowed_flows}",
            "Habilite o grant type correto no app client, normalmente 'code' para Authorization Code Flow.",
        )

    requested_scopes = [s for s in args.scope.replace("+", " ").split() if s]
    missing_scopes = [s for s in requested_scopes if s not in allowed_scopes]
    if missing_scopes:
        add_check(
            checks,
            "oauth-scopes",
            "MEDIUM",
            "WARN",
            f"Alguns scopes do teste não aparecem em AllowedOAuthScopes: {missing_scopes}. Scopes permitidos: {allowed_scopes}",
            "Ajuste os scopes solicitados pela aplicação ou habilite os scopes necessários no app client.",
        )
    else:
        add_check(
            checks,
            "oauth-scopes",
            "INFO",
            "PASS",
            f"Scopes solicitados no teste parecem permitidos: {requested_scopes}",
            "Nenhuma ação necessária para este item.",
        )

    if supported_idps:
        add_check(
            checks,
            "supported-idps",
            "INFO",
            "PASS",
            f"Identity providers associados: {supported_idps}",
            "Confirme se o IdP usado pela aplicação está nesta lista.",
        )
    else:
        add_check(
            checks,
            "supported-idps",
            "MEDIUM",
            "WARN",
            "Nenhum SupportedIdentityProviders foi retornado para o app client.",
            "Verifique se ao menos Cognito ou o IdP externo necessário está associado ao app client.",
        )

    if expected_logouts:
        for uri in expected_logouts:
            if uri in logout_urls:
                add_check(
                    checks,
                    f"expected-logout:{uri}",
                    "INFO",
                    "PASS",
                    f"A logout_uri esperada está cadastrada: {uri}",
                    "Nenhuma ação necessária para este item.",
                )
            else:
                add_check(
                    checks,
                    f"expected-logout:{uri}",
                    "MEDIUM",
                    "FAIL",
                    f"A logout_uri esperada NÃO está cadastrada: {uri}",
                    "Adicione essa URL exata em LogoutURLs se ela for usada no parâmetro logout_uri.",
                )

    return sorted(checks, key=lambda c: (SEVERITY_ORDER.get(c.severity, 99), c.id))


def find_near_matches(target: str, candidates: List[str]) -> List[str]:
    parsed_target = urllib.parse.urlparse(target)
    near: List[str] = []
    for candidate in candidates:
        parsed_candidate = urllib.parse.urlparse(candidate)
        if (
            parsed_candidate.netloc == parsed_target.netloc
            or parsed_candidate.path.rstrip("/") == parsed_target.path.rstrip("/")
        ):
            near.append(candidate)
    return near[:5]


def build_authorize_url(
    domain: str,
    client_id: str,
    redirect_uri: Optional[str],
    response_type: str,
    scope: str,
) -> str:
    domain = domain.strip()
    if domain.startswith("https://"):
        base = domain.rstrip("/")
    elif domain.startswith("http://"):
        base = "https://" + domain[len("http://") :].rstrip("/")
    else:
        base = "https://" + domain.rstrip("/")

    params = {
        "response_type": response_type,
        "client_id": client_id,
        "scope": scope,
        "state": "cognito-audit-state",
    }
    if redirect_uri:
        params["redirect_uri"] = redirect_uri
    return f"{base}/oauth2/authorize?{urllib.parse.urlencode(params)}"


def probe_authorize(url: str) -> ProbeResult:
    request = urllib.request.Request(
        url, method="GET", headers={"User-Agent": "cognito-audit/1.0"}
    )
    opener = urllib.request.build_opener(NoRedirectHandler)
    try:
        response = opener.open(request, timeout=15)
        return ProbeResult(
            authorize_url=url,
            http_status=response.status,
            location=response.headers.get("Location"),
            error=None,
            raw_exception=None,
        )
    except urllib.error.HTTPError as exc:
        return ProbeResult(
            authorize_url=url,
            http_status=exc.code,
            location=exc.headers.get("Location"),
            error=None,
            raw_exception=None,
        )
    except urllib.error.URLError as exc:
        return ProbeResult(
            authorize_url=url,
            http_status=None,
            location=None,
            error=str(exc.reason),
            raw_exception=repr(exc),
        )
    except Exception as exc:  # pragma: no cover
        return ProbeResult(
            authorize_url=url,
            http_status=None,
            location=None,
            error=str(exc),
            raw_exception=repr(exc),
        )


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def summarize_probe(probe: ProbeResult) -> CheckResult:
    location = probe.location or ""
    parsed = urllib.parse.urlparse(location)
    params = urllib.parse.parse_qs(parsed.query)
    error = params.get("error", [None])[0]
    if error == "redirect_mismatch":
        return CheckResult(
            id="hosted-ui-probe",
            severity="CRITICAL",
            status="FAIL",
            message=f"Probe do Hosted UI retornou redirect_mismatch. HTTP={probe.http_status}, Location={location}",
            recommendation="Confirme se a redirect_uri usada no probe está exatamente em CallbackURLs. Se o probe omitiu redirect_uri, configure DefaultRedirectURI ou envie redirect_uri explicitamente.",
        )
    if error:
        return CheckResult(
            id="hosted-ui-probe",
            severity="MEDIUM",
            status="WARN",
            message=f"Probe do Hosted UI retornou erro OAuth '{error}'. HTTP={probe.http_status}, Location={location}",
            recommendation="Analise o erro retornado. Se não for redirect_mismatch, verifique parâmetros obrigatórios, scopes, fluxo OAuth e IdP.",
        )
    if probe.location:
        return CheckResult(
            id="hosted-ui-probe",
            severity="INFO",
            status="PASS",
            message=f"Probe do Hosted UI redirecionou sem redirect_mismatch. HTTP={probe.http_status}, Location={probe.location}",
            recommendation="O redirect_uri testado parece aceito por Cognito; prossiga com testes funcionais de login.",
        )
    return CheckResult(
        id="hosted-ui-probe",
        severity="LOW",
        status="INFO",
        message=f"Probe concluído sem Location. HTTP={probe.http_status}, erro={probe.error}",
        recommendation="Revise conectividade, domínio informado e resposta completa se necessário.",
    )


def render_markdown(
    args: argparse.Namespace,
    client: Dict[str, Any],
    checks: List[CheckResult],
    probe: Optional[ProbeResult],
) -> str:
    callback_urls = client.get("CallbackURLs", []) or []
    logout_urls = client.get("LogoutURLs", []) or []
    allowed_flows = client.get("AllowedOAuthFlows", []) or []
    allowed_scopes = client.get("AllowedOAuthScopes", []) or []
    supported_idps = client.get("SupportedIdentityProviders", []) or []
    generated_at = datetime.now(timezone.utc).isoformat()

    lines = [
        "# Relatório de Auditoria do Amazon Cognito",
        "",
        f"Gerado em: `{generated_at}`",
        "",
        "## Escopo",
        "",
        f"Este relatório avaliou o app client `{args.client_id}` no User Pool `{args.user_pool_id}`, região `{args.region}`, com foco em causas comuns de `redirect_mismatch`.",
        "",
        "## Configuração observada",
        "",
        "| Campo | Valor |",
        "|---|---|",
        f"| ClientName | `{client.get('ClientName', '')}` |",
        f"| ClientId | `{client.get('ClientId', '')}` |",
        f"| AllowedOAuthFlowsUserPoolClient | `{client.get('AllowedOAuthFlowsUserPoolClient', False)}` |",
        f"| AllowedOAuthFlows | `{', '.join(allowed_flows) if allowed_flows else '-'}` |",
        f"| AllowedOAuthScopes | `{', '.join(allowed_scopes) if allowed_scopes else '-'}` |",
        f"| SupportedIdentityProviders | `{', '.join(supported_idps) if supported_idps else '-'}` |",
        f"| DefaultRedirectURI | `{client.get('DefaultRedirectURI', '-')}` |",
        f"| CallbackURLs | `{len(callback_urls)}` cadastrada(s) |",
        f"| LogoutURLs | `{len(logout_urls)}` cadastrada(s) |",
        "",
        "## Resultado dos checks",
        "",
        "| Severidade | Status | Check | Diagnóstico | Recomendação |",
        "|---|---|---|---|---|",
    ]
    for check in checks:
        lines.append(
            f"| {check.severity} | {check.status} | `{check.id}` | {escape_md(check.message)} | {escape_md(check.recommendation)} |"
        )

    lines.extend(["", "## Callback URLs cadastradas", ""])
    if callback_urls:
        lines.extend(["| # | URL |", "|---:|---|"])
        for idx, url in enumerate(callback_urls, 1):
            lines.append(f"| {idx} | `{url}` |")
    else:
        lines.append("Nenhuma callback URL cadastrada foi retornada pela API.")

    lines.extend(["", "## Logout URLs cadastradas", ""])
    if logout_urls:
        lines.extend(["| # | URL |", "|---:|---|"])
        for idx, url in enumerate(logout_urls, 1):
            lines.append(f"| {idx} | `{url}` |")
    else:
        lines.append("Nenhuma logout URL cadastrada foi retornada pela API.")

    if probe:
        lines.extend(
            [
                "",
                "## Probe do Hosted UI",
                "",
                "| Campo | Valor |",
                "|---|---|",
                f"| Authorize URL testada | `{probe.authorize_url}` |",
                f"| HTTP status | `{probe.http_status}` |",
                f"| Location | `{probe.location}` |",
                f"| Erro de conexão | `{probe.error}` |",
            ]
        )

    lines.extend(
        [
            "",
            "## Próximos passos recomendados",
            "",
            "Valide a URL real produzida pela aplicação antes do redirecionamento para Cognito e compare o valor decodificado de `redirect_uri` com a lista de `CallbackURLs`. A comparação deve ser exata, considerando protocolo, host, porta, path e barra final. Caso a aplicação omita `redirect_uri`, configure `DefaultRedirectURI` e garanta que ela também esteja presente em `CallbackURLs`.",
        ]
    )
    return "\n".join(lines) + "\n"


def escape_md(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def main() -> int:
    args = parse_args()
    cognito = boto3_client(args.region, args.profile)
    client = describe_client(cognito, args.user_pool_id, args.client_id)
    checks = validate_client_config(client, args)

    probe: Optional[ProbeResult] = None
    if args.probe_hosted_ui:
        if not args.domain:
            add_check(
                checks,
                "hosted-ui-probe",
                "MEDIUM",
                "WARN",
                "--probe-hosted-ui foi informado, mas --domain não foi fornecido.",
                "Informe o domínio do Hosted UI para executar o probe.",
            )
        else:
            redirect_for_probe = (
                args.expected_redirect_uri[0] if args.expected_redirect_uri else None
            )
            authorize_url = build_authorize_url(
                args.domain,
                args.client_id,
                redirect_for_probe,
                args.response_type,
                args.scope,
            )
            probe = probe_authorize(authorize_url)
            checks.append(summarize_probe(probe))
            checks = sorted(
                checks, key=lambda c: (SEVERITY_ORDER.get(c.severity, 99), c.id)
            )

    if args.format == "json":
        report_obj = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "input": vars(args),
            "client": sanitize_client(client),
            "checks": [asdict(c) for c in checks],
            "probe": asdict(probe) if probe else None,
        }
        output = (
            json.dumps(report_obj, indent=2, ensure_ascii=False, default=str) + "\n"
        )
    else:
        output = render_markdown(args, client, checks, probe)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)
    else:
        print(output, end="")

    has_fail = any(
        c.status == "FAIL" and c.severity in {"CRITICAL", "HIGH"} for c in checks
    )
    return 1 if has_fail else 0


def sanitize_client(client: Dict[str, Any]) -> Dict[str, Any]:
    hidden_keys = {"ClientSecret"}
    sanitized: Dict[str, Any] = {}
    for key, value in client.items():
        if key in hidden_keys and value:
            sanitized[key] = "***REDACTED***"
        else:
            sanitized[key] = value
    return sanitized


if __name__ == "__main__":
    raise SystemExit(main())
