// halla-nettest: cliente de teste do protocolo Halla (ver PROTOCOL.md).
// Conecta dois clientes simulados e valida: login, chat, canais, movimento,
// poke, moderação (kick/ban), estados e relay de voz UDP.
// Uso: halla-nettest [host] [porta]   (precisa de um halla-server rodando)

#include <QCoreApplication>
#include <QTcpSocket>
#include <QUdpSocket>
#include <QNetworkDatagram>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QTimer>
#include <QElapsedTimer>
#include <QRandomGenerator>
#include <cmath>

#include "HallaProtocol.h"

static int g_pass = 0, g_fail = 0;
#define CHECK(cond, name) do { \
    if (cond) { ++g_pass; printf("  [OK] %s\n", name); } \
    else      { ++g_fail; printf("  [FALHOU] %s\n", name); } \
} while (0)

class FakeClient : public QObject {
public:
    QTcpSocket tcp;
    QUdpSocket udp;
    QByteArray buf;
    QList<QJsonObject> inbox;
    int id = 0;
    quint32 token = 0;
    QString nick;

    explicit FakeClient(const QString& n) : nick(n) {
        connect(&tcp, &QTcpSocket::readyRead, this, [this] {
            buf += tcp.readAll();
            int i;
            while ((i = buf.indexOf('\n')) >= 0) {
                QByteArray line = buf.left(i).trimmed();
                buf = buf.mid(i + 1);
                if (line.isEmpty()) continue;
                inbox << QJsonDocument::fromJson(line).object();
            }
        });
    }

    void send(const QJsonObject& o) { tcp.write(QJsonDocument(o).toJson(QJsonDocument::Compact) + '\n'); }

    bool connectTo(const QString& host, quint16 port) {
        tcp.connectToHost(host, port);
        return tcp.waitForConnected(3000);
    }

    QJsonObject waitFor(const QString& type, int ms = 3000) {
        QElapsedTimer t; t.start();
        while (t.elapsed() < ms) {
            for (int i = 0; i < inbox.size(); ++i)
                if (inbox[i]["t"].toString() == type)
                    return inbox.takeAt(i);
            QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        }
        return {};
    }

    bool had(const QString& type) {
        for (const QJsonObject& o : inbox) if (o["t"].toString() == type) return true;
        return false;
    }
};

int main(int argc, char* argv[]) {
    QCoreApplication app(argc, argv);
    const QString host = argc > 1 ? QString::fromLatin1(argv[1]) : "127.0.0.1";
    const quint16 port = argc > 2 ? quint16(QString::fromLatin1(argv[2]).toUShort()) : 9987;

    printf("=== Teste do protocolo Halla contra %s:%d ===\n\n", qPrintable(host), port);

    // ---------- cliente A entra
    FakeClient A("Alice");
    CHECK(A.connectTo(host, port), "A conecta ao TCP");
    QByteArray uidA = QByteArray(21, 0);
    for (int i = 0; i < 21; ++i) uidA[i] = char(QRandomGenerator::global()->generate());
    QJsonObject hello = HProto::msg("hello");
    hello["proto"] = HProto::kProtoVersion;
    hello["uid"] = QString::fromLatin1(uidA.toBase64());
    hello["nick"] = "Alice";
    hello["ver"] = "3.6.2"; hello["platform"] = "Linux";
    A.send(hello);
    QJsonObject w = A.waitFor("welcome");
    CHECK(w["t"].toString() == "welcome", "A recebe welcome");
    A.id = w["selfId"].toInt();
    CHECK(A.id > 0, "A recebe id");
    CHECK(w["channels"].toArray().size() >= 1, "welcome tem canais");
    A.token = w["voice"].toObject()["token"].toString().toUInt();
    CHECK(A.token >= 1024, "A recebe token de voz");

    // ---------- apelido duplicado deve falhar
    FakeClient Dup("Alice");
    CHECK(Dup.connectTo(host, port), "Dup conecta ao TCP");
    hello["nick"] = "Alice";
    hello["uid"] = "outro-id";
    Dup.send(hello);
    QJsonObject err = Dup.waitFor("error");
    CHECK(err["code"].toString() == "name_in_use", "apelido duplicado rejeitado");

    // ---------- cliente B entra e vê A
    FakeClient B("Bob");
    B.connectTo(host, port);
    hello["nick"] = "Bob";
    hello["uid"] = "uid-bob-0000000000000000000=";
    B.send(hello);
    QJsonObject wb = B.waitFor("welcome");
    B.id = wb["selfId"].toInt();
    B.token = wb["voice"].toObject()["token"].toString().toUInt();
    CHECK(B.id > 0 && B.id != A.id, "B recebe id diferente");
    bool seesA = false;
    for (const QJsonValue& v : wb["users"].toArray())
        if (v.toObject()["name"].toString() == "Alice") seesA = true;
    CHECK(seesA, "B vê Alice na lista de usuários");
    QJsonObject joinedA = A.waitFor("user_joined");
    CHECK(joinedA["user"].toObject()["name"].toString() == "Bob", "A notificado de que B entrou");

    // ---------- chat do servidor
    QJsonObject chat = HProto::msg("chat");
    chat["scope"] = "server";
    chat["text"] = "Olá [b]servidor[/b]!";
    A.send(chat);
    QJsonObject chatB = B.waitFor("chat");
    CHECK(chatB["fromName"].toString() == "Alice", "B recebe chat de servidor de A");

    // ---------- criar canal temporário e mover
    QJsonObject cc = HProto::msg("chan_create");
    cc["name"] = "Sala de testes";
    cc["parent"] = 0;
    cc["type"] = 0;
    cc["codec"] = 4; cc["quality"] = 6; cc["max"] = -1;
    B.send(cc);
    QJsonObject cu = A.waitFor("chan_update");
    const int newChan = cu["chan"].toObject()["id"].toInt();
    CHECK(newChan > 1, "canal criado (temp)");
    QJsonObject mv = HProto::msg("move");
    mv["channel"] = newChan;
    B.send(mv);
    QJsonObject um = A.waitFor("user_moved");
    CHECK(um["id"].toInt() == B.id && um["channel"].toInt() == newChan, "B moveu para o novo canal (A viu)");

    // ---------- chat de canal: A não deve receber (A está no canal padrão)
    A.waitFor("chat"); // consome a cópia do chat de servidor anterior
    chat["scope"] = "channel";
    chat["text"] = "segredo do canal";
    B.send(chat);
    bool aGotChannelChat = A.waitFor("chat", 700).contains("text");
    CHECK(!aGotChannelChat, "A NÃO recebe chat de canal alheio");

    // ---------- poke
    QJsonObject poke = HProto::msg("poke");
    poke["to"] = A.id;
    poke["msg"] = "vem pro canal!";
    B.send(poke);
    QJsonObject pk = A.waitFor("poke");
    CHECK(pk["from"].toInt() == B.id, "A recebeu poke de B");

    // ---------- estados (mic mudo / away)
    QJsonObject st = HProto::msg("status");
    st["mic"] = true; st["away"] = true;
    A.send(st);
    QJsonObject us = B.waitFor("user_state");
    CHECK(us["id"].toInt() == A.id && us["mic"].toBool() && us["away"].toBool(),
          "B viu estados de A (mic mudo + ausente)");

    // ---------- ping/pong com RTT
    QElapsedTimer rt; rt.start();
    QJsonObject pg = HProto::msg("ping");
    pg["ts"] = 42;
    A.send(pg);
    QJsonObject po = A.waitFor("pong");
    CHECK(po["ts"].toInt() == 42, QString("pong (RTT %1 ms)").arg(rt.elapsed()).toUtf8().constData());

    // ---------- VOZ: move A para o mesmo canal de B e testa o relay
    mv["channel"] = newChan;
    A.send(mv);
    // espera o broadcast do movimento de A (com id certo; descarta mensagens antigas)
    {
        bool sawMove = false;
        QElapsedTimer tw; tw.start();
        while (tw.elapsed() < 3000 && !sawMove) {
            QJsonObject m = B.waitFor("user_moved", 400);
            if (m["id"].toInt() == A.id && m["channel"].toInt() == newChan) sawMove = true;
            QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
        }
        CHECK(sawMove, "B viu A entrar no canal");
    }

    A.udp.bind(0);
    B.udp.bind(0);
    // A registra seu endpoint UDP (pacote com payload vazio), como o cliente real faz
    A.udp.writeDatagram(HProto::encodeVoiceClient(A.token, 1, QByteArray()), QHostAddress(host), port);
    QElapsedTimer settle; settle.start();
    while (settle.elapsed() < 250) QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
    // pacote de voz de B (payload opus fake — relay não valida conteúdo)
    QByteArray opusFake(160, 0);
    for (int i = 0; i < 160; ++i) opusFake[i] = char(i);
    QByteArray vp = HProto::encodeVoiceClient(B.token, 1, opusFake);
    B.udp.writeDatagram(vp, QHostAddress(host), port);
    // A deve receber o relay: magic|fromId|seq|payload
    QByteArray got;
    QElapsedTimer t2; t2.start();
    while (t2.elapsed() < 2000 && got.isEmpty()) {
        while (A.udp.hasPendingDatagrams()) {
            QNetworkDatagram dg = A.udp.receiveDatagram();
            got = dg.data();
        }
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
    }
    bool voiceOk = got.size() == 170 && memcmp(got.constData(), "HALL", 4) == 0;
    quint32 fromId = 0;
    if (voiceOk) memcpy(&fromId, got.constData() + 4, 4);
    CHECK(voiceOk && int(fromId) == B.id, "relay de voz: A recebeu frame de B no mesmo canal");

    // ---------- permissões: B (normal) NÃO pode banir
    QJsonObject ban = HProto::msg("ban");
    ban["id"] = A.id; ban["reason"] = "teste"; ban["minutes"] = 0;
    B.send(ban);
    QJsonObject permErr = B.waitFor("error");
    CHECK(permErr["code"].toString() == "no_permission", "usuário normal não pode banir");

    // ---------- kick de canal por admin: usa chave de privilégio
    QJsonObject pkck = HProto::msg("privkey");
    pkck["key"] = "HL3-AAAA-BBBB-CCCC";
    B.send(pkck);
    QJsonObject grp = A.waitFor("user_group");
    CHECK(grp["group"].toString() == "admin", "chave de privilégio vira admin");
    QJsonObject kickc = HProto::msg("kick");
    kickc["id"] = A.id; kickc["from"] = "channel"; kickc["reason"] = "teste de kick";
    A.waitFor("user_group"); // consome eco
    B.send(kickc);
    // A deve voltar para o canal padrão (descarta user_moved antigos na caixa de A)
    bool backToDefault = false;
    {
        QElapsedTimer tw; tw.start();
        while (tw.elapsed() < 3000 && !backToDefault) {
            QJsonObject back = A.waitFor("user_moved", 400);
            if (back["id"].toInt() == A.id && back["channel"].toInt() == 1) backToDefault = true;
        }
    }
    CHECK(backToDefault, "kick de canal: A voltou ao canal padrão");

    // ---------- desconexão limpa
    QJsonObject quit = HProto::msg("quit");
    B.send(quit);
    QJsonObject left = A.waitFor("user_left", 3000);
    CHECK(left["id"].toInt() == B.id, "A viu B sair");

    printf("\n=== Resultado: %d OK, %d falhas ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
