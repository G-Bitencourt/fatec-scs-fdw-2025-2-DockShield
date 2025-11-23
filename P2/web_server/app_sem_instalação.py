import os
import markdown
import jwt
from functools import wraps

from bson import ObjectId
from flask import Flask, redirect, render_template, request, url_for
from pymongo import MongoClient

# ================================================== #
# SEÇÃO 1: CONFIGURAÇÕES E INICIALIZAÇÃO
# ================================================== #

app = Flask(__name__)
CVES_POR_PAGINA = 100

# ========== Conexão com Banco de Dados ========== #
try:
    mongo_uri = "mongodb://localhost:27017/"
    client = MongoClient(mongo_uri)
    # client.admin.command("ping")  # Comentei para evitar travar na inicialização
    db = client["DockShield"]
except Exception:
    db = None

# IMPORTANTE: Essas configurações devem bater com o Node.js
JWT_SECRET = "53D0jjbsjTb6Of+e0O>+na&p@UO0M!Z<_sUx.d*-c+ND"
URL_LOGIN_NODE = "http://localhost:3000/login.html"

# ================================================== #
# SEÇÃO 1.5: DECORATOR DE AUTENTICAÇÃO (A FECHADURA)
# ================================================== #

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 1. Tenta pegar o cookie que o Node.js gravou
        token = request.cookies.get('auth_token')

        # 2. Se não tiver token, manda pro Login
        if not token:
            return redirect(URL_LOGIN_NODE)

        try:
            # 3. Tenta abrir o token usando a chave secreta
            dados_usuario = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            
        except jwt.ExpiredSignatureError:
            # Token venceu
            return redirect(URL_LOGIN_NODE)
        except jwt.InvalidTokenError:
            # Token falso ou inválido
            return redirect(URL_LOGIN_NODE)

        # 4. Se tudo der certo, executa a rota original
        return f(*args, **kwargs)
    return decorated_function

# ================================================== #
# SEÇÃO 2: ROTAS DO APLICATIVO (PROTEGIDAS)
# ================================================== #

# ========== Rota Principal (Index) ========== #
@app.route("/")
@login_required  # <--- FALTAVA ISSO AQUI
def index():
    """Renderiza a página inicial."""
    colecoes = db.list_collection_names() if db is not None else []
    return render_template("index.html", colecoes=colecoes)


# ========== Rota de Detalhes da Imagem ========== #
@app.route("/docker/<colecao>")
@login_required  # <--- E ISSO AQUI
def docker_details(colecao):
    """Exibe o relatório de análise principal de uma imagem (coleção)."""
    if db is None:
        return "<p>Banco de dados não disponível.</p>"

    doc_analise_imagem = db[colecao].find_one({"analise_do_container": {"$exists": True}})
    analise_imagem_html = None

    if doc_analise_imagem:
        try:
            content_markdown = doc_analise_imagem["analise_do_container"]["choices"][0]["message"]["content"]
            analise_imagem_html = markdown.markdown(content_markdown)
        except Exception:
            analise_imagem_html = "<p>Erro ao carregar o relatório de análise da imagem.</p>"

    return render_template("docker.html", colecao=colecao, analise_imagem_html=analise_imagem_html)


# ========== Rota da Lista de CVEs (Paginada) ========== #
@app.route("/cve-list/<colecao>")
@login_required  # <--- E ISSO AQUI
def cve_list(colecao):
    """Exibe uma lista paginada de CVEs para uma coleção específica."""
    if db is None:
        return "<p>Banco de dados não disponível.</p>"

    page = request.args.get("page", 1, type=int)
    skip = (page - 1) * CVES_POR_PAGINA

    query_cve = {"cve": {"$exists": True}}
    total_cves = db[colecao].count_documents(query_cve)
    total_pages = (total_cves + CVES_POR_PAGINA - 1) // CVES_POR_PAGINA if CVES_POR_PAGINA > 0 else 0

    documentos_cve = db[colecao].find(query_cve).skip(skip).limit(CVES_POR_PAGINA)
    docs_cve_list = [{**doc, "_id": str(doc["_id"])} for doc in documentos_cve]

    return render_template(
        "cve.html",
        colecao=colecao,
        documentos=docs_cve_list,
        page=page,
        total_pages=total_pages,
        total_cves=total_cves,
    )


# ========== Rota do Resumo da CVE ========== #
@app.route("/resumo/<colecao>/<id>")
@login_required  # <--- E ISSO AQUI
def resumo(colecao, id):
    """Exibe o relatório detalhado (resumo) de uma CVE específica."""
    if db is None:
        return redirect(url_for("cve_list", colecao=colecao))

    try:
        object_id_instance = ObjectId(id)
    except Exception:
        return redirect(url_for("cve_list", colecao=colecao))

    doc = db[colecao].find_one({"_id": object_id_instance})

    if doc:
        doc["_id"] = str(doc["_id"])
        doc["colecao"] = colecao
        try:
            content_markdown = doc["relatorio"]["choices"][0]["message"]["content"]
            content_html = markdown.markdown(content_markdown)
        except Exception:
            content_html = "<p>Erro ao carregar o conteúdo do relatório.</p>"

        return render_template("relatorio.html", doc=doc, content_html=content_html, colecao=colecao)

    return redirect(url_for("cve_list", colecao=colecao))

# ================================================== #
# SEÇÃO 3: INÍCIO DO PROGRAMA
# ================================================== #
if __name__ == "__main__":
    # Usa IP fixo para evitar travamento de DNS no Windows
    app.run(host="127.0.0.1", port=5000, debug=True)