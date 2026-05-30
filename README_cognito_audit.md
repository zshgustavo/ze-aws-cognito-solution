# Script de Auditoria do Amazon Cognito para `redirect_mismatch`

Este pacote contém um script Python para auditar um **App Client do Amazon Cognito** e identificar configurações que normalmente causam o erro `redirect_mismatch`. O script foi desenvolvido para ser compatível com **Windows e Linux**, usando `boto3` para consultar a API da AWS e bibliotecas padrão do Python para realizar um probe opcional no Hosted UI.

> O script é somente leitura. Ele não altera configurações no Cognito, não cria recursos e não executa ações destrutivas.

## Arquivos

| Arquivo | Descrição |
|---|---|
| `cognito_audit.py` | Script principal de auditoria. |
| `README_cognito_audit.md` | Este guia de uso. |
| `requirements.txt` | Dependência Python necessária. |



## Observações importantes

A comparação de `redirect_uri` em Cognito é sensível a diferenças de protocolo, host, porta, path e barra final. Por exemplo, `https://app.exemplo.com/callback` e `https://app.exemplo.com/callback/` devem ser tratados como valores diferentes para fins de auditoria.

Se a aplicação estiver atrás de proxy, API Gateway, ALB, NGINX, CloudFront ou Ingress Kubernetes, valide se ela está gerando a URL pública correta. Um erro comum é a aplicação montar callback com `http://`, host interno ou porta interna, enquanto o Cognito espera a URL pública HTTPS.

## Referências

[1]: https://docs.aws.amazon.com/cognito/latest/developerguide/authorization-endpoint.html "Amazon Cognito: The redirect and authorization endpoint"
[2]: https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateUserPoolClient.html "Amazon Cognito API Reference: UpdateUserPoolClient"
[3]: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-client-apps.html "Amazon Cognito: Application-specific settings with app clients"
