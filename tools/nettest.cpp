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

    // ==================================================================
    //  CENÁRIO 3 (protocolo v2): permissões granulares, grupos, banlist,
    //  chaves de uso único, senha de canal, talk power, persistência.
    // ==================================================================
    const QString uidAStr = QString::fromLatin1(uidA.toBase64());

    // 24) welcome v2 traz grupos e myPerms
    CHECK(w["groups"].toArray().size() >= 3 && w.contains("myPerms"),
          "welcome v2 traz grupos + myPerms");

    // 25) group_list requisitado explicitamente
    A.send(HProto::msg("group_list"));
    QJsonObject gl = A.waitFor("group_list");
    CHECK(gl["groups"].toArray().size() >= 3, "group_list com >= 3 grupos");

    // 26) C entra como admin (adminPassword do INI)
    FakeClient C("Carol");
    CHECK(C.connectTo(host, port), "C conecta ao TCP");
    hello = HProto::msg("hello");
    hello["proto"] = HProto::kProtoVersion;
    hello["uid"] = "uid-carol-000000000000000000=";
    hello["nick"] = "Carol";
    hello["adminPass"] = "troque-esta-senha";
    C.send(hello);
    QJsonObject wc = C.waitFor("welcome");
    C.id = wc["selfId"].toInt();
    C.token = wc["voice"].toObject()["token"].toString().toUInt();
    CHECK(wc["myPerms"].toObject()["*"].toBool(), "admin entra com adminPass (perms *)");

    // 27) ban: C bane A (A recebe kicked com ban=true)
    // nota: A já tinha um "kicked" ANTIGO na caixa (kick de canal da v1) —
    // filtrar até chegar o com ban=true
    QJsonObject banA = HProto::msg("ban");
    banA["id"] = A.id; banA["reason"] = "teste de ban v2"; banA["minutes"] = 0;
    C.send(banA);
    {
        bool gotBanKick = false;
        QElapsedTimer tw; tw.start();
        while (tw.elapsed() < 3000 && !gotBanKick) {
            QJsonObject k = A.waitFor("kicked", 400);
            if (k["ban"].toBool()) gotBanKick = true;
        }
        CHECK(gotBanKick, "A recebeu kicked (ban=true)");
    }
    A.tcp.waitForDisconnected(1500);

    // 28) A tenta reconectar com o mesmo UID -> banned
    FakeClient A2("Alice");
    A2.connectTo(host, port);
    hello["uid"] = uidAStr; hello["nick"] = "Alice"; hello["adminPass"] = "";
    A2.send(hello);
    QJsonObject e = A2.waitFor("error");
    CHECK(e["code"].toString() == "banned", "UID banido não reconecta");

    // 29) banlist: C vê o ban de A (por uid)
    C.send(HProto::msg("banlist"));
    QJsonObject bl = C.waitFor("banlist");
    bool foundBan = false;
    for (const QJsonValue& v : bl["bans"].toArray())
        if (v.toObject()["uid"].toString() == uidAStr) foundBan = true;
    CHECK(foundBan, "banlist contém o UID banido");

    // 30) unban: C remove o ban; A reconecta com sucesso
    QJsonObject un = HProto::msg("unban");
    un["uid"] = uidAStr;
    C.send(un);
    QJsonObject br = C.waitFor("ban_removed");
    CHECK(br["uid"].toString() == uidAStr, "unban confirmado (ban_removed)");
    FakeClient A3("Alice");
    A3.connectTo(host, port);
    A3.send(hello);
    QJsonObject wa3 = A3.waitFor("welcome");
    CHECK(wa3["selfId"].toInt() > 0, "reconexão OK após unban");
    A3.id = wa3["selfId"].toInt();

    // 31) D entra (normal) e usa chave de privilégio -> admin
    FakeClient D("Dave");
    D.connectTo(host, port);
    hello["uid"] = "uid-dave-0000000000000000000=";
    hello["nick"] = "Dave";
    D.send(hello);
    QJsonObject wd = D.waitFor("welcome");
    D.id = wd["selfId"].toInt();
    D.token = wd["voice"].toObject()["token"].toString().toUInt();
    QJsonObject useKey = HProto::msg("privkey");
    useKey["key"] = "HL3-DDDD-EEEE-FFFF";
    D.send(useKey);
    {
        bool became = false;
        QElapsedTimer tw; tw.start();
        while (tw.elapsed() < 3000 && !became) {
            QJsonObject g = D.waitFor("user_group", 400);
            if (g["id"].toInt() == D.id && g["group"].toString() == "admin") became = true;
        }
        CHECK(became, "chave de privilégio (2ª) vira admin");
    }

    // 32) MESMA chave de novo -> privkey_used (uso único persistente)
    FakeClient E("Eve");
    E.connectTo(host, port);
    hello["uid"] = "uid-eve-00000000000000000000=";
    hello["nick"] = "Eve";
    E.send(hello);
    QJsonObject we = E.waitFor("welcome");
    E.id = we["selfId"].toInt();
    E.send(useKey);
    QJsonObject keyErr = E.waitFor("error");
    CHECK(keyErr["code"].toString() == "privkey_used",
          "chave de uso único rejeitada na 2ª vez");

    // 33) chave com grupo alvo (@normal): vira normal, não admin
    FakeClient F("Fred");
    F.connectTo(host, port);
    hello["uid"] = "uid-fred-0000000000000000000=";
    hello["nick"] = "Fred";
    F.send(hello);
    F.waitFor("welcome");
    QJsonObject keyN = HProto::msg("privkey");
    keyN["key"] = "HL3-CONV-1234-5678";
    F.send(keyN);
    {
        bool normalKey = false, noErr = true;
        QElapsedTimer tw; tw.start();
        while (tw.elapsed() < 2500) {
            QJsonObject g = F.waitFor("user_group", 300);
            if (g.isEmpty()) break;
            if (g["group"].toString() == "normal") normalKey = true;
        }
        CHECK(normalKey, "chave @normal concede grupo normal (não admin)");
    }

    // 34-36) canal com senha: entra só com a senha certa; admin ignora
    QJsonObject mkpw = HProto::msg("chan_create");
    mkpw["name"] = "Camarote"; mkpw["type"] = 0; mkpw["pass"] = "segredo123";
    mkpw["codec"] = 4; mkpw["quality"] = 6; mkpw["max"] = -1;
    D.send(mkpw); // D é admin
    QJsonObject chU = A3.waitFor("chan_update");
    const int pwChan = chU["chan"].toObject()["id"].toInt();
    CHECK(pwChan > 1, "canal com senha criado");
    QJsonObject jmv = HProto::msg("move");
    jmv["channel"] = pwChan;
    E.send(jmv); // sem senha
    QJsonObject passErr = E.waitFor("error");
    CHECK(passErr["code"].toString() == "bad_channel_pass",
          "entrar sem senha -> bad_channel_pass");
    jmv["pass"] = "segredo123";
    E.send(jmv);
    {
        bool inChan = false; QElapsedTimer tw; tw.start();
        while (tw.elapsed() < 3000 && !inChan) {
            QJsonObject m = A3.waitFor("user_moved", 400);
            if (m["id"].toInt() == E.id && m["channel"].toInt() == pwChan) inChan = true;
        }
        CHECK(inChan, "entrou com a senha correta");
    }
    {
        // D (admin) entra SEM informar a senha
        QJsonObject mv2 = HProto::msg("move");
        mv2["channel"] = pwChan;
        D.send(mv2);
        bool inChan = false; QElapsedTimer tw; tw.start();
        while (tw.elapsed() < 3000 && !inChan) {
            QJsonObject m = A3.waitFor("user_moved", 400);
            if (m["id"].toInt() == D.id && m["channel"].toInt() == pwChan) inChan = true;
        }
        CHECK(inChan, "admin entra sem senha (ignoreChanPass)");
    }

    // 37-38) talk power: canal moderado com ntalk=60
    QJsonObject chEd = HProto::msg("chan_edit");
    chEd["id"] = pwChan; chEd["moderated"] = true; chEd["ntalk"] = 60;
    D.send(chEd);
    {
        QJsonObject upd = A3.waitFor("chan_update");
        CHECK(upd["chan"].toObject()["ntalk"].toInt() == 60, "canal editado (moderado, ntalk=60)");
    }
    QJsonObject tk = HProto::msg("talking");
    tk["on"] = true;
    E.send(tk); // E é normal (talkPower 25) < 60
    QJsonObject talkErr = E.waitFor("error");
    CHECK(talkErr["code"].toString() == "no_talk_power",
          "talk power insuficiente -> no_talk_power");
    D.send(tk); // D admin (75) ok
    {
        bool sawTalk = false; QElapsedTimer tw; tw.start();
        while (tw.elapsed() < 2500 && !sawTalk) {
            QJsonObject u = E.waitFor("user_state", 400);
            if (u["id"].toInt() == D.id && u["talking"].toBool()) sawTalk = true;
        }
        CHECK(sawTalk, "admin fala no canal moderado (user_state visto)");
        D.send(HProto::msg("talking")); D.waitFor("user_group", 200);
        QJsonObject tkOff = HProto::msg("talking"); tkOff["on"] = false; D.send(tkOff);
    }

    // 39-40) move_other: quem não pode não move; admin move
    QJsonObject mo = HProto::msg("move_other");
    mo["id"] = D.id; mo["channel"] = 1;
    E.send(mo);
    QJsonObject moErr = E.waitFor("error");
    CHECK(moErr["code"].toString() == "no_permission", "normal não move outros");
    D.send(mo); // D admin move E? não — move D... mover E para o padrão
    mo["id"] = E.id;
    D.send(mo);
    {
        bool moved = false; QElapsedTimer tw; tw.start();
        while (tw.elapsed() < 3000 && !moved) {
            QJsonObject m = E.waitFor("user_moved", 400);
            if (m["id"].toInt() == E.id && m["channel"].toInt() == 1) moved = true;
        }
        CHECK(moved, "admin moveu outro cliente (move_other)");
    }

    // 41-42) atribuição de grupo por UID persiste após reconexão
    A3.send(HProto::msg("group_list")); // drena A3
    QJsonObject asg = HProto::msg("client_set_group");
    asg["id"] = E.id; asg["gid"] = 1; // E -> guest
    D.send(asg);
    {
        bool guestNow = false; QElapsedTimer tw; tw.start();
        while (tw.elapsed() < 3000 && !guestNow) {
            QJsonObject g = E.waitFor("user_group", 400);
            if (g["id"].toInt() == E.id && g["group"].toString() == "guest") guestNow = true;
        }
        CHECK(guestNow, "client_set_group online -> guest");
    }
    E.send(HProto::msg("quit"));
    E.tcp.waitForDisconnected(1500);
    FakeClient E2("Eve");
    E2.connectTo(host, port);
    hello["uid"] = "uid-eve-00000000000000000000="; hello["nick"] = "Eve";
    E2.send(hello);
    QJsonObject we2 = E2.waitFor("welcome");
    E2.id = we2["selfId"].toInt();
    CHECK(we2["myPerms"].toObject()["talkPower"].toInt() == 10,
          "atribuição por UID persiste (reconectou como guest, talkPower 10)");

    // 43) guest NÃO pode criar canal (sem chanCreateTemp)
    QJsonObject mk2 = HProto::msg("chan_create");
    mk2["name"] = "NaoPode"; mk2["type"] = 0; mk2["codec"] = 4;
    E2.send(mk2);
    QJsonObject mkErr = E2.waitFor("error");
    CHECK(mkErr["code"].toString() == "no_permission", "guest não cria canal");

    // 44) anti-lockout: não remover "*" do grupo admin
    QJsonObject gs = HProto::msg("group_set");
    gs["id"] = 3; gs["perms"] = QJsonObject{{"poke", true}};
    D.send(gs);
    QJsonObject lockErr = D.waitFor("error");
    CHECK(lockErr["code"].toString() == "locked", "anti-lockout do grupo admin (*)");

    // 45-46) grupo customizado "vip" + atribuição
    QJsonObject mkG = HProto::msg("group_set");
    mkG["name"] = "vip";
    mkG["perms"] = QJsonObject{{"poke", true}, {"privmsg", true},
                               {"chanCreateTemp", true}, {"talkPower", 40}};
    D.send(mkG);
    int vipId = 0;
    {
        QElapsedTimer tw; tw.start();
        while (tw.elapsed() < 3000 && !vipId) {
            QJsonObject l = E2.waitFor("group_list", 400);
            for (const QJsonValue& v : l["groups"].toArray())
                if (v.toObject()["name"].toString() == "vip")
                    vipId = v.toObject()["id"].toInt();
        }
        CHECK(vipId >= 100, "grupo customizado 'vip' criado (id>=100)");
    }
    QJsonObject asg2 = HProto::msg("client_set_group");
    asg2["id"] = E2.id; asg2["gid"] = vipId;
    D.send(asg2);
    {
        bool vipNow = false; QElapsedTimer tw; tw.start();
        while (tw.elapsed() < 3000 && !vipNow) {
            QJsonObject g = E2.waitFor("user_group", 400);
            if (g["id"].toInt() == E2.id && g["group"].toString() == "vip") vipNow = true;
        }
        CHECK(vipNow, "E2 atribuída ao grupo vip");
    }
    E2.send(mk2); // vip TEM chanCreateTemp
    {
        // filtrar: D tem chan_updates antigos ("Camarote", edição) na caixa
        bool created = false;
        QElapsedTimer tw; tw.start();
        while (tw.elapsed() < 3000 && !created) {
            QJsonObject cu2 = D.waitFor("chan_update", 400);
            if (cu2["chan"].toObject()["name"].toString() == "NaoPode") created = true;
        }
        CHECK(created, "vip cria canal temporário (permissão granular)");
    }

    // 47) server_edit: muda nome e propaga a todos
    QJsonObject se = HProto::msg("server_edit");
    se["name"] = "Halla v2 Teste";
    D.send(se);
    QJsonObject seb = E2.waitFor("server_edit");
    CHECK(seb["name"].toString() == "Halla v2 Teste", "server_edit propaga novo nome");

    // 48) group_set exige groupEdit: E2 (vip) não gerencia grupos
    QJsonObject gs2 = HProto::msg("group_set");
    gs2["name"] = "hax";
    E2.send(gs2);
    QJsonObject ge2 = E2.waitFor("error");
    CHECK(ge2["code"].toString() == "no_permission", "sem groupEdit não cria grupo");

    // 49) banlist exige banList: E2 não lista bans
    E2.send(HProto::msg("banlist"));
    QJsonObject blErr = E2.waitFor("error");
    CHECK(blErr["code"].toString() == "no_permission", "sem banList não vê banlist");

    // ==================================================================
    //  v3: avatares, mensagens offline, reclamações, operador de canal,
    //      sussurro (whisper) e transferência de arquivos
    // ==================================================================

    // 50-51) avatar: D sobe um avatar; todo mundo vê o hash; avatar_get devolve
    QByteArray pic(2048, 0);
    for (int i = 0; i < pic.size(); ++i) pic[i] = char(i * 7);
    QJsonObject avs = HProto::msg("avatar_set");
    avs["data"] = QString::fromLatin1(pic.toBase64());
    D.send(avs);
    {
        bool sawHash = false; QElapsedTimer tw; tw.start();
        while (tw.elapsed() < 3000 && !sawHash) {
            QJsonObject ua = E2.waitFor("user_avatar", 400);
            if (ua["id"].toInt() == D.id && !ua["av"].toString().isEmpty()) sawHash = true;
        }
        CHECK(sawHash, "avatar_set: hash do avatar propagado (user_avatar)");
    }
    QJsonObject avg = HProto::msg("avatar_get");
    avg["uid"] = "uid-dave-0000000000000000000=";
    E2.send(avg);
    QJsonObject avd = E2.waitFor("avatar_data");
    CHECK(QByteArray::fromBase64(avd["data"].toString().toLatin1()) == pic,
          "avatar_get: conteúdo idêntico ao enviado");

    // 52-53) offline: C sai; D deixa mensagem; C volta e recebe
    const QString uidC = "uid-carol-000000000000000000=";
    C.send(HProto::msg("quit"));
    C.tcp.waitForDisconnected(1500);
    QJsonObject om = HProto::msg("offline_send");
    om["uid"] = uidC; om["text"] = "volta quando puder!";
    D.send(om);
    QJsonObject oms = D.waitFor("offline_sent");
    CHECK(oms["uid"].toString() == uidC, "offline_send confirmado");
    FakeClient C2("Carol");
    C2.connectTo(host, port);
    hello["uid"] = uidC; hello["nick"] = "Carol";
    C2.send(hello);
    QJsonObject wc2 = C2.waitFor("welcome");
    C2.id = wc2["selfId"].toInt();
    C2.token = wc2["voice"].toObject()["token"].toString().toUInt();
    QJsonObject omd = C2.waitFor("offline_msg");
    CHECK(omd["text"].toString() == "volta quando puder!" && omd["fromName"].toString() == "Dave",
          "mensagem offline entregue no login");

    // 54-55) reclamações: E2 reclama de C2; D (com banList) lista e limpa
    QJsonObject cp = HProto::msg("complaint_add");
    // E2 vê o user_joined de Carol (ela já estava conectada quando C2 entrou)
    int idC2 = -1;
    {
        QElapsedTimer tw; tw.start();
        while (tw.elapsed() < 2000 && idC2 < 0) {
            QJsonObject j = E2.waitFor("user_joined", 300);
            if (j["user"].toObject()["name"].toString() == "Carol")
                idC2 = j["user"].toObject()["id"].toInt();
        }
    }
    CHECK(idC2 > 0, "E2 viu Carol entrar (id conhecido)");
    cp["id"] = idC2; cp["text"] = "flood no chat geral";
    E2.send(cp);
    QJsonObject cpa = E2.waitFor("complaint_added");
    CHECK(cpa["t"].toString() == "complaint_added", "reclamação registrada");
    D.send(HProto::msg("complaint_list"));
    QJsonObject cpl = D.waitFor("complaint_list");
    bool foundCp = false;
    for (const QJsonValue& v : cpl["complaints"].toArray())
        if (v.toObject()["text"].toString() == "flood no chat geral") foundCp = true;
    CHECK(foundCp, "reclamação visível na lista (admin)");
    QJsonObject cpc = HProto::msg("complaint_clear");
    D.send(cpc);
    QJsonObject ccl = D.waitFor("complaint_cleared");
    CHECK(ccl["t"].toString() == "complaint_cleared", "reclamações limpas (admin)");

    // 56-58) sussurro: D sussurra só para C2; E2 (mesmo canal) NÃO ouve, C2 ouve
    {
        QJsonObject wh = HProto::msg("whisper");
        QJsonArray ids2; ids2 << idC2;
        wh["ids"] = ids2;
        D.send(wh);
        QJsonObject wo = D.waitFor("whisper_ok");
        CHECK(wo["count"].toInt() == 1, "whisper definido (1 alvo)");
    }
    {
        // E2 recebeu token no seu welcome? Não guardamos: pedir voice_token
        if (!E2.token) {
            E2.send(HProto::msg("voice_hello"));
            QJsonObject vt = E2.waitFor("voice_token");
            E2.token = vt["token"].toString().toUInt();
        }
        // registrar endpoints UDP de E2 e C2 (pacote vazio)
        C2.udp.bind(0); E2.udp.bind(0);
        C2.udp.writeDatagram(HProto::encodeVoiceClient(C2.token, 1, QByteArray()), QHostAddress(host), port);
        E2.udp.writeDatagram(HProto::encodeVoiceClient(E2.token, 1, QByteArray()), QHostAddress(host), port);
        QElapsedTimer s2; s2.start();
        while (s2.elapsed() < 250) QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        // D fala (payload fake); espera-se: C2 recebe, E2 não
        QByteArray opusFake2(120, 0); opusFake2.fill(0x55);
        D.udp.bind(0);
        D.udp.writeDatagram(HProto::encodeVoiceClient(D.token, 7, opusFake2), QHostAddress(host), port);
        bool c2got = false, e2got = false;
        QElapsedTimer t3; t3.start();
        while (t3.elapsed() < 1500) {
            while (C2.udp.hasPendingDatagrams()) { C2.udp.receiveDatagram(); c2got = true; }
            while (E2.udp.hasPendingDatagrams()) { E2.udp.receiveDatagram(); e2got = true; }
            QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        }
        CHECK(c2got, "sussurro: C2 (alvo) recebeu a voz");
        CHECK(!e2got, "sussurro: E2 (mesmo canal, não-alvo) NÃO recebeu");
        // limpa sussurro de D
        QJsonObject wh = HProto::msg("whisper"); wh["ids"] = QJsonArray();
        D.send(wh); D.waitFor("whisper_ok");
    }

    // 59-62) arquivos: D envia arquivo ao canal padrão; C2 lista; E2 baixa; D exclui
    QByteArray fdata(4096, 0);
    for (int i = 0; i < fdata.size(); ++i) fdata[i] = char(i * 3);
    QJsonObject fu = HProto::msg("ft_upload");
    fu["channel"] = 1; fu["name"] = "teste v3.txt";
    fu["data"] = QString::fromLatin1(fdata.toBase64());
    D.send(fu);
    QJsonObject fup = D.waitFor("ft_uploaded");
    CHECK(fup["name"].toString() == "teste v3.txt", "ft_upload confirmado");
    QJsonObject fl = HProto::msg("ft_list"); fl["channel"] = 1;
    C2.send(fl);
    QJsonObject flr = C2.waitFor("ft_list");
    bool foundFile = false;
    for (const QJsonValue& v : flr["files"].toArray())
        if (v.toObject()["name"].toString() == "teste v3.txt") foundFile = true;
    CHECK(foundFile, "ft_list mostra o arquivo");
    QJsonObject fd = HProto::msg("ft_download");
    fd["channel"] = 1; fd["name"] = "teste v3.txt";
    E2.send(fd);
    QJsonObject fdd = E2.waitFor("ft_data");
    CHECK(QByteArray::fromBase64(fdd["data"].toString().toLatin1()) == fdata,
          "ft_download: conteúdo idêntico");
    QJsonObject fdel = HProto::msg("ft_delete");
    fdel["channel"] = 1; fdel["name"] = "teste v3.txt";
    D.send(fdel);
    QJsonObject fdr = D.waitFor("ft_deleted");
    CHECK(fdr["t"].toString() == "ft_deleted", "ft_delete pelo uploader");

    // 63-64) operador de canal: E2 criou o canal "NaoPode" (é op lá, mas NÃO é admin)
    //        -> pode expulsar gente DAQUELE canal; não pode expulsar do servidor
    int nopChan = 0;
    {
        // descobre o id do canal "NaoPode" via lista do próprio welcome de E2? usar group_list não.
        // E2 criou; o chan_update foi visto por D, mas E2 recebeu o dela também:
        QElapsedTimer tw; tw.start();
        while (tw.elapsed() < 2000 && !nopChan) {
            QJsonObject cu = E2.waitFor("chan_update", 300);
            if (cu["chan"].toObject()["name"].toString() == "NaoPode")
                nopChan = cu["chan"].toObject()["id"].toInt();
        }
    }
    if (nopChan) {
        // A3 entra no canal de E2 (A3 está no canal padrão — sem senha no NaoPode)
        QJsonObject mvA = HProto::msg("move"); mvA["channel"] = nopChan;
        A3.send(mvA);
        QJsonObject mvE = HProto::msg("move"); mvE["channel"] = nopChan;
        E2.send(mvE);
        A3.waitFor("user_moved", 800);
        QJsonObject kck = HProto::msg("kick");
        kck["id"] = A3.id; kck["from"] = "channel"; kck["reason"] = "regra do canal";
        E2.send(kck);
        bool backAgain = false; QElapsedTimer tw2; tw2.start();
        while (tw2.elapsed() < 3000 && !backAgain) {
            QJsonObject m = A3.waitFor("user_moved", 400);
            if (m["id"].toInt() == A3.id && m["channel"].toInt() == 1) backAgain = true;
        }
        CHECK(backAgain, "operador expulsa do próprio canal sem ser admin");
        QJsonObject ksv = HProto::msg("kick");
        ksv["id"] = A3.id; ksv["from"] = "server";
        E2.send(ksv);
        QJsonObject ksvErr = E2.waitFor("error");
        CHECK(ksvErr["code"].toString() == "no_permission",
              "operador NÃO expulsa do servidor");
    } else {
        CHECK(false, "operador (canal NaoPode não encontrado)");
    }

    printf("\n=== Resultado: %d OK, %d falhas ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
