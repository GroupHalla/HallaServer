#include "ServerCore.h"
#include "ClientSession.h"
#include "VoiceRelay.h"
#include "HallaProtocol.h"

#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonArray>
#include <QDateTime>
#include <QDir>
#include <QCryptographicHash>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QRandomGenerator>
#include <algorithm>

ServerCore::ServerCore(QObject* parent) : QObject(parent) {
    m_nextToken = 1024;
    m_idleTimer = new QTimer(this);
    m_idleTimer->setInterval(5000);
    connect(m_idleTimer, &QTimer::timeout, this, &ServerCore::checkIdleClients);
    setupBuiltinGroups();
}

ServerCore::~ServerCore() {
    saveData();
    saveBans();
    qDeleteAll(m_clients);
}

bool ServerCore::start(quint16 controlPort, quint16 voicePort) {
    m_controlPort = controlPort;
    loadData();
    loadBans();
    loadServerBanner();
    loadAvatars();

    m_tcp = new QTcpServer(this);
    connect(m_tcp, &QTcpServer::newConnection, this, &ServerCore::onNewConnection);
    if (!m_tcp->listen(QHostAddress::Any, controlPort)) {
        log(QStringLiteral("FALHA: não foi possível escutar na porta TCP %1: %2")
                .arg(controlPort).arg(m_tcp->errorString()));
        return false;
    }
    log(QStringLiteral("Controle TCP escutando na porta %1").arg(controlPort));

    m_voice = new VoiceRelay(this, this);
    if (!m_voice->bind(voicePort)) return false;

    m_idleTimer->start();
    log(QStringLiteral("Servidor \"%1\" v%2 iniciado (slots: %3, protocolo v%4)")
            .arg(m_name, m_version).arg(m_maxClients).arg(HProto::kProtoVersion));
    return true;
}

void ServerCore::log(const QString& msg) {
    const QString line = QStringLiteral("[%1] %2")
        .arg(QDateTime::currentDateTime().toString("dd/MM/yyyy HH:mm:ss"), msg);
    emit logLine(line);
}

void ServerCore::sendError(ClientSession* c, const QString& code, const QString& msg) {
    QJsonObject e = HProto::msg("error");
    e["code"] = code;
    e["msg"] = msg;
    c->send(e);
}

// ================================================== grupos e permissões (v2)
void ServerCore::setupBuiltinGroups() {
    GroupDef guest;  guest.id = 1;  guest.name = "guest";
    guest.perms = QJsonObject{
        {"poke", true}, {"privmsg", true}, {"talkPower", 10}
    };
    GroupDef normal; normal.id = 2; normal.name = "normal";
    normal.perms = QJsonObject{
        {"poke", true}, {"privmsg", true}, {"chanCreateTemp", true},
        {"talkPower", 25}
    };
    GroupDef admin;  admin.id = 3;  admin.name = "admin";
    admin.perms = QJsonObject{
        {"*", true}, {"kick", true}, {"ban", true}, {"banList", true},
        {"move", true}, {"setCommander", true}, {"selfCommander", true},
        {"b_client_set_channel_commander", true},
        {"b_client_is_channel_commander", true},
        {"chanCreateTemp", true}, {"chanCreateSemi", true},
        {"chanCreatePerm", true}, {"chanEdit", true}, {"chanDelete", true},
        {"serverEdit", true}, {"groupEdit", true}, {"poke", true},
        {"privmsg", true}, {"ignoreChanPass", true}, {"ignoreTalkPower", true},
        {"talkPower", 75}
    };
    m_groups[1] = guest;
    m_groups[2] = normal;
    m_groups[3] = admin;
}

bool ServerCore::hasPerm(const ClientSession* c, const char* key) const {
    if (!c) return false;
    
    // OVERRIDE TOTAL: Qualquer um no grupo admin (id 3 ou nome admin), ou usando o nickname "serveradmin",
    // ou se o UID estiver mapeado permanentemente para o grupo administrador (3) possui controle ABSOLUTO.
    if (c->groupId() == 3 || c->group().toLower() == "admin" || c->name() == QStringLiteral("serveradmin")) {
        return true;
    }
    
    if (m_assignByUid.value(c->uniqueId(), 1) == 3) {
        return true;
    }

    const GroupDef g = m_groups.value(c->groupId(), m_groups.value(1));
    if (g.id == 3 || g.name.toLower() == "admin" || g.perms.value(QStringLiteral("*")).toBool()) {
        return true;
    }
    
    const QJsonValue value = g.perms.value(QString::fromLatin1(key));
    return value.toBool() || value.toInt(0) > 0;
}

bool ServerCore::hasChannelPerm(const ClientSession* c, int channelId, const QString& permKey) const {
    if (!c) return false;
    
    // Bypass absoluto de administrador / serveradmin
    if (c->groupId() == 3 || c->group().toLower() == "admin" || c->name() == QStringLiteral("serveradmin")) {
        return true;
    }
    
    // Se o canal não existe, retorna true por padrão (usa permissões globais)
    if (!m_channels.contains(channelId)) return true;
    
    const SvrChan& ch = m_channels[channelId];

    // Se o grupo do usuário tem uma regra específica configurada neste canal.
    const QString gidStr = QString::number(c->groupId());
    if (ch.groupPerms.contains(gidStr)) {
        const QJsonObject gPerms = ch.groupPerms[gidStr].toObject();
        // "Percorrer" é a permissão de alcance do canal; sem ela não há
        // entrada mesmo que "Entrar" esteja herdando a regra global.
        if (permKey == QStringLiteral("join") && gPerms.contains("traverse")
                && !gPerms.value("traverse").toBool()) return false;
        if (gPerms.contains(permKey)) return gPerms.value(permKey).toBool();
    }

    return true;
}

int ServerCore::talkPower(const ClientSession* c) const {
    if (!c) return 0;
    const GroupDef g = m_groups.value(c->groupId(), m_groups.value(1));
    return g.perms.value(QStringLiteral("talkPower")).toInt();
}

QJsonObject ServerCore::myPermsOf(const GroupDef& g) { return g.perms; }

int ServerCore::groupIdByName(const QString& name) const {
    for (const GroupDef& g : m_groups)
        if (g.name.compare(name, Qt::CaseInsensitive) == 0) return g.id;
    return 0;
}

QJsonObject ServerCore::groupToJson(const GroupDef& g) const {
    QJsonObject o;
    o["id"] = g.id;
    o["name"] = g.name;
    o["perms"] = g.perms;
    o["sigla"] = g.sigla;
    o["order"] = g.order;
    o["icon"] = g.icon;
    return o;
}

void ServerCore::applyGroup(ClientSession* c, int groupId, bool announce) {
    if (!m_groups.contains(groupId)) groupId = 1;
    c->setGroupId(groupId);
    c->setGroup(m_groups[groupId].name);
    c->setSigla(m_groups[groupId].sigla);
    c->setIcon(m_groups[groupId].icon);
    c->setGroupOrder(m_groups[groupId].order);
    if (announce) {
        QJsonObject m = HProto::msg("user_group");
        m["id"] = c->id();
        m["group"] = c->group();
        m["gid"] = groupId;
        m["sigla"] = m_groups[groupId].sigla;
        m["icon"] = m_groups[groupId].icon;
        m["order"] = m_groups[groupId].order;
        broadcast(m);
    }
}

void ServerCore::broadcastGroups() {
    QJsonObject m = HProto::msg("group_list");
    QJsonArray arr;
    for (const GroupDef& g : m_groups) arr << groupToJson(g);
    m["groups"] = arr;
    broadcast(m);
}

// ==================================================================== dados
void ServerCore::loadData() {
    m_channels.clear();
    m_groups.clear();
    setupBuiltinGroups();

    SvrChan def{1, 0, QStringLiteral("Canal padrão"), QString(), QString(), QString(),
                true, false, false, 0, 2, 4, 6, -1, 96};
    m_channels.insert(1, def);
    m_nextChanId = 2;

    if (!initDatabase()) {
        log("Erro grave: Não foi possível inicializar o banco de dados SQLite!");
        return;
    }

    QSqlDatabase db = QSqlDatabase::database("HallaServerConnection");
    if (!db.isOpen()) return;

    QSqlQuery q(db);
    
    bool dbHasData = false;
    if (q.exec("SELECT COUNT(*) FROM settings") && q.next()) {
        if (q.value(0).toInt() > 0) {
            dbHasData = true;
        }
    }
    
    if (!dbHasData && !m_dataFile.isEmpty() && QFile::exists(m_dataFile)) {
        log("Detectados arquivos JSON antigos. Iniciando migração automática para SQLite...");
        loadDataFromJson();
        if (QFile::exists(m_banFile)) {
            loadBansFromJson();
        }
        saveDataToSql();
        saveBansToSql();
        
        QFile::rename(m_dataFile, m_dataFile + ".bak");
        if (QFile::exists(m_banFile)) {
            QFile::rename(m_banFile, m_banFile + ".bak");
        }
        log("Migração para SQLite concluída com sucesso! Arquivos .json renomeados para .json.bak");
        return;
    }

    if (dbHasData) {
        if (q.exec("SELECT key, value FROM settings")) {
            while (q.next()) {
                QString key = q.value(0).toString();
                QString val = q.value(1).toString();
                if (key == "name") m_name = val;
                else if (key == "motd") m_motd = val;
                else if (key == "queryPass") m_queryPass = val;
            }
        }

        if (q.exec("SELECT id, parentId, name, topic, desc, password, isDefault, type, moderated, codec, codecQuality, maxClients, ntalk, bitrate, group_perms, no_symbol, order_index, linked_channels FROM channels")) {
            while (q.next()) {
                SvrChan c;
                c.id = q.value(0).toInt();
                c.parent = q.value(1).toInt();
                c.name = q.value(2).toString();
                c.topic = q.value(3).toString();
                c.desc = q.value(4).toString();
                c.password = q.value(5).toString();
                c.def = q.value(6).toInt() != 0;
                c.type = q.value(7).toInt();
                c.moderated = q.value(8).toInt() != 0;
                c.codec = q.value(9).toInt();
                c.quality = q.value(10).toInt();
                c.maxClients = q.value(11).toInt();
                c.ntalk = q.value(12).toInt();
                c.bitrate = q.value(13).toInt();
                if (c.bitrate <= 0) c.bitrate = 96;
                c.groupPerms = QJsonDocument::fromJson(q.value(14).toString().toUtf8()).object();
                c.noSymbol = q.value(15).toInt() != 0;
                c.order = q.value(16).toInt();
                const QJsonDocument linkedDoc = QJsonDocument::fromJson(q.value(17).toString().toUtf8());
                for (const QJsonValue& value : linkedDoc.array()) {
                    const int linkedId = value.toInt();
                    if (linkedId > 0 && linkedId != c.id && !c.linkedChannels.contains(linkedId))
                        c.linkedChannels << linkedId;
                }
                
                if (c.id == 1) {
                    m_channels[1] = c;
                } else {
                    m_channels.insert(c.id, c);
                }
                m_nextChanId = qMax(m_nextChanId, c.id + 1);
            }
        }

        if (q.exec("SELECT id, name, sigla, order_index, icon, perms FROM groups")) {
            while (q.next()) {
                GroupDef g;
                g.id = q.value(0).toInt();
                g.name = q.value(1).toString();
                g.sigla = q.value(2).toString();
                g.order = q.value(3).toInt();
                g.icon = q.value(4).toString();
                
                QJsonDocument doc = QJsonDocument::fromJson(q.value(5).toString().toUtf8());
                g.perms = doc.object();
                
                if (g.id >= 100) {
                    m_groups[g.id] = g;
                    m_nextGroupId = qMax(m_nextGroupId, g.id + 1);
                } else {
                    // Atualiza campos de sigla, order e icon nos grupos built-in carregados
                    if (m_groups.contains(g.id)) {
                        m_groups[g.id].sigla = g.sigla;
                        m_groups[g.id].order = g.order;
                        m_groups[g.id].icon = g.icon;
                    }
                }
            }
        }

        if (q.exec("SELECT uid, groupId FROM assignments")) {
            while (q.next()) {
                m_assignByUid[q.value(0).toString()] = q.value(1).toInt();
            }
        }

        if (q.exec("SELECT key_val FROM used_keys")) {
            while (q.next()) {
                m_usedKeys.insert(q.value(0).toString());
            }
        }

        if (q.exec("SELECT uid, name, firstSeen, lastSeen FROM clients")) {
            while (q.next()) {
                RegClient rc;
                rc.name = q.value(1).toString();
                rc.firstSeen = QDateTime::fromString(q.value(2).toString(), Qt::ISODate);
                rc.lastSeen = QDateTime::fromString(q.value(3).toString(), Qt::ISODate);
                m_registry[q.value(0).toString()] = rc;
            }
        }

        m_complaints.clear();
        if (q.exec("SELECT uid, name, byUid, byName, text, ts FROM complaints")) {
            while (q.next()) {
                Complaint cp;
                cp.uid = q.value(0).toString();
                cp.name = q.value(1).toString();
                cp.byUid = q.value(2).toString();
                cp.byName = q.value(3).toString();
                cp.text = q.value(4).toString();
                cp.ts = QDateTime::fromString(q.value(5).toString(), Qt::ISODate);
                m_complaints << cp;
            }
        }

        m_offline.clear();
        if (q.exec("SELECT targetUid, fromUid, fromName, text, ts FROM offline_messages")) {
            while (q.next()) {
                OfflineMsg om;
                QString targetUid = q.value(0).toString();
                om.fromUid = q.value(1).toString();
                om.fromName = q.value(2).toString();
                om.text = q.value(3).toString();
                om.ts = QDateTime::fromString(q.value(4).toString(), Qt::ISODate);
                m_offline[targetUid] << om;
            }
        }

        m_files.clear();
        if (q.exec("SELECT chanId, name, byUid, byName, size, ts FROM files")) {
            while (q.next()) {
                FileMeta fm;
                fm.chan = q.value(0).toInt();
                fm.name = q.value(1).toString();
                fm.byUid = q.value(2).toString();
                fm.by = q.value(3).toString();
                fm.size = q.value(4).toLongLong();
                fm.ts = QDateTime::fromString(q.value(5).toString(), Qt::ISODate);
                m_files << fm;
            }
        }
    }
    
    // Carrega ou gera chave de privilégio dinâmica se nenhuma estiver definida no .ini
    QSqlDatabase dbConn = QSqlDatabase::database("HallaServerConnection");
    if (dbConn.isOpen() && m_privKeyGroup.isEmpty()) {
        QSqlQuery q(dbConn);
        QString savedKey;
        q.prepare("SELECT `value` FROM settings WHERE `key` = :k");
        q.bindValue(":k", "generatedPrivilegeKey");
        if (q.exec() && q.next()) {
            savedKey = q.value(0).toString();
        }
        
        if (savedKey.isEmpty()) {
            // Gera uma nova chave segura estilo TS3
            const QString chars = QStringLiteral("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
            savedKey = QStringLiteral("HL3-");
            for (int block = 0; block < 4; ++block) {
                for (int i = 0; i < 4; ++i) {
                    savedKey += chars.at(int(QRandomGenerator::global()->bounded(chars.length())));
                }
                if (block < 3) {
                    savedKey += '-';
                }
            }
            
            // Salva no banco de dados
            q.prepare("INSERT INTO settings (`key`, `value`) VALUES (:k, :v)");
            q.bindValue(":k", "generatedPrivilegeKey");
            q.bindValue(":v", savedKey);
            q.exec();
            
            // Exibe a chave de forma destacada no console!
            log(QStringLiteral("\n"
                               "=================================================================\n"
                               "  CHAVE DE PRIVILÉGIO ADMINISTRADOR GERADA AUTOMATICAMENTE:\n"
                               "  %1\n"
                               "  Insira esta chave no seu cliente para obter privilégio total!\n"
                               "=================================================================\n").arg(savedKey));
        }
        
        m_privKeyGroup[savedKey] = QStringLiteral("admin");
    }
    
    log(QStringLiteral("Dados carregados do SQLite: %1 canais, %2 grupos, %3 identidades")
            .arg(m_channels.size()).arg(m_groups.size()).arg(m_registry.size()));
}

bool ServerCore::initDatabase() {
    QSqlDatabase db;
    if (m_dbType == "mysql") {
        db = QSqlDatabase::addDatabase("QMYSQL", "HallaServerConnection");
        db.setHostName(m_dbHost);
        db.setPort(m_dbPort);
        db.setDatabaseName(m_dbName);
        db.setUserName(m_dbUser);
        db.setPassword(m_dbPassword);
    } else {
        db = QSqlDatabase::addDatabase("QSQLITE", "HallaServerConnection");
        db.setDatabaseName(m_dbFile);
    }

    if (!db.open()) {
        log(QStringLiteral("Erro ao abrir banco de dados (%1): %2")
            .arg(m_dbType, db.lastError().text()));
        return false;
    }
    
    QSqlQuery q(db);
    
    q.exec("CREATE TABLE IF NOT EXISTS settings ("
           "`key` VARCHAR(255) PRIMARY KEY, "
           "`value` TEXT"
           ")");
           
    q.exec("CREATE TABLE IF NOT EXISTS channels ("
           "`id` INT PRIMARY KEY, "
           "`parentId` INT, "
           "`name` VARCHAR(255), "
           "`topic` VARCHAR(255), "
           "`desc` TEXT, "
           "`password` VARCHAR(255), "
           "`isDefault` INT, "
           "`type` INT, "
           "`moderated` INT, "
           "`codec` INT, "
           "`codecQuality` INT, "
           "`maxClients` INT, "
           "`ntalk` INT, "
           "`bitrate` INT, "
           "`group_perms` TEXT, "
           "`no_symbol` INT DEFAULT 0, "
           "`order_index` INT DEFAULT 0, "
           "`linked_channels` TEXT"
           ")");
    // Migração silenciosa de bancos criados antes das opções visuais e de
    // áudio vinculado. O erro de coluna já existente é intencionalmente
    // ignorado para manter bancos atuais compatíveis.
    q.exec("ALTER TABLE channels ADD COLUMN `no_symbol` INT DEFAULT 0");
    q.exec("ALTER TABLE channels ADD COLUMN `order_index` INT DEFAULT 0");
    q.exec("ALTER TABLE channels ADD COLUMN `linked_channels` TEXT");
           
    q.exec("CREATE TABLE IF NOT EXISTS groups ("
           "`id` INT PRIMARY KEY, "
           "`name` VARCHAR(255), "
           "`sigla` VARCHAR(255), "
           "`order_index` INT, "
           "`icon` VARCHAR(255), "
           "`perms` TEXT"
           ")");
           
    q.exec("CREATE TABLE IF NOT EXISTS assignments ("
           "`uid` VARCHAR(255) PRIMARY KEY, "
           "`groupId` INT"
           ")");
           
    q.exec("CREATE TABLE IF NOT EXISTS used_keys ("
           "`key_val` VARCHAR(255) PRIMARY KEY"
           ")");
           
    q.exec("CREATE TABLE IF NOT EXISTS clients ("
           "`uid` VARCHAR(255) PRIMARY KEY, "
           "`name` VARCHAR(255), "
           "`firstSeen` VARCHAR(255), "
           "`lastSeen` VARCHAR(255)"
           ")");
           
    q.exec("CREATE TABLE IF NOT EXISTS bans ("
           "`uid` VARCHAR(255), "
           "`ip` VARCHAR(255), "
           "`name` VARCHAR(255), "
           "`reason` TEXT, "
           "`expires` VARCHAR(255), "
           "PRIMARY KEY (`uid`, `ip`)"
           ")");

    if (m_dbType == "mysql") {
        q.exec("CREATE TABLE IF NOT EXISTS complaints ("
               "`id` INT AUTO_INCREMENT PRIMARY KEY, "
               "`uid` VARCHAR(255), "
               "`name` VARCHAR(255), "
               "`byUid` VARCHAR(255), "
               "`byName` VARCHAR(255), "
               "`text` TEXT, "
               "`ts` VARCHAR(255)"
               ")");
        q.exec("CREATE TABLE IF NOT EXISTS offline_messages ("
               "`id` INT AUTO_INCREMENT PRIMARY KEY, "
               "`targetUid` VARCHAR(255), "
               "`fromUid` VARCHAR(255), "
               "`fromName` VARCHAR(255), "
               "`text` TEXT, "
               "`ts` VARCHAR(255)"
               ")");
        q.exec("CREATE TABLE IF NOT EXISTS files ("
               "`id` INT AUTO_INCREMENT PRIMARY KEY, "
               "`chanId` INT, "
               "`name` VARCHAR(255), "
               "`byUid` VARCHAR(255), "
               "`byName` VARCHAR(255), "
               "`size` BIGINT, "
               "`ts` VARCHAR(255)"
               ")");
    } else {
        q.exec("CREATE TABLE IF NOT EXISTS complaints ("
               "`id` INTEGER PRIMARY KEY AUTOINCREMENT, "
               "`uid` TEXT, "
               "`name` TEXT, "
               "`byUid` TEXT, "
               "`byName` TEXT, "
               "`text` TEXT, "
               "`ts` TEXT"
               ")");
        q.exec("CREATE TABLE IF NOT EXISTS offline_messages ("
               "`id` INTEGER PRIMARY KEY AUTOINCREMENT, "
               "`targetUid` TEXT, "
               "`fromUid` TEXT, "
               "`fromName` TEXT, "
               "`text` TEXT, "
               "`ts` TEXT"
               ")");
        q.exec("CREATE TABLE IF NOT EXISTS files ("
               "`id` INTEGER PRIMARY KEY AUTOINCREMENT, "
               "`chanId` INTEGER, "
               "`name` TEXT, "
               "`byUid` TEXT, "
               "`byName` TEXT, "
               "`size` INTEGER, "
               "`ts` TEXT"
               ")");
    }
    
    return true;
}

void ServerCore::loadDataFromJson() {
    if (m_dataFile.isEmpty()) return;
    QFile f(m_dataFile);
    if (!f.open(QIODevice::ReadOnly)) return;
    QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
    if (!doc.isObject()) return;
    QJsonObject root = doc.object();

    QJsonArray chans = root["channels"].toArray();
    for (const QJsonValue& v : chans) {
        SvrChan c = chanFromJson(v.toObject());
        if (c.id == 1) {
            m_channels[1].name = c.name; m_channels[1].topic = c.topic; m_channels[1].desc = c.desc;
            m_channels[1].password = c.password; m_channels[1].def = true; m_channels[1].moderated = c.moderated;
            m_channels[1].ntalk = c.ntalk;
            m_channels[1].type = 2; m_channels[1].codec = c.codec; m_channels[1].quality = c.quality;
            m_channels[1].maxClients = c.maxClients;
            m_channels[1].bitrate = c.bitrate;
            m_channels[1].noSymbol = c.noSymbol;
            m_channels[1].linkedChannels = c.linkedChannels;
            continue;
        }
        m_channels.insert(c.id, c);
        m_nextChanId = qMax(m_nextChanId, c.id + 1);
    }
    if (root.contains("name")) m_name = root["name"].toString();
    if (root.contains("motd")) m_motd = root["motd"].toString();

    for (const QJsonValue& v : root["groups"].toArray()) {
        const QJsonObject o = v.toObject();
        GroupDef g;
        g.id = o["id"].toInt();
        g.name = o["name"].toString();
        g.perms = o["perms"].toObject();
        g.sigla = o["sigla"].toString();
        g.order = o["order"].toInt(0);
        g.icon = o["icon"].toString();
        if (g.id >= 100 && !g.name.isEmpty()) {
            m_groups[g.id] = g;
            m_nextGroupId = qMax(m_nextGroupId, g.id + 1);
        } else if (m_groups.contains(g.id)) {
            m_groups[g.id].sigla = g.sigla;
            m_groups[g.id].order = g.order;
            m_groups[g.id].icon = g.icon;
        }
    }
    const QJsonObject assign = root["assignments"].toObject();
    for (auto it = assign.begin(); it != assign.end(); ++it)
        m_assignByUid[it.key()] = it.value().toInt();
    for (const QJsonValue& v : root["usedKeys"].toArray())
        m_usedKeys.insert(v.toString());
    const QJsonObject clients = root["clients"].toObject();
    for (auto it = clients.begin(); it != clients.end(); ++it) {
        const QJsonObject o = it.value().toObject();
        RegClient rc;
        rc.name = o["name"].toString();
        rc.firstSeen = QDateTime::fromString(o["first"].toString(), Qt::ISODate);
        rc.lastSeen = QDateTime::fromString(o["last"].toString(), Qt::ISODate);
        m_registry[it.key()] = rc;
    }
    m_queryPass = root["queryPass"].toString();
    for (const QJsonValue& v : root["complaints"].toArray()) {
        const QJsonObject o = v.toObject();
        Complaint cp{o["uid"].toString(), o["name"].toString(), o["byUid"].toString(),
                     o["byName"].toString(), o["text"].toString(),
                     QDateTime::fromString(o["ts"].toString(), Qt::ISODate)};
        m_complaints << cp;
    }
    const QJsonObject off = root["offline"].toObject();
    for (auto it = off.begin(); it != off.end(); ++it) {
        for (const QJsonValue& v : it.value().toArray()) {
            const QJsonObject o = v.toObject();
            m_offline[it.key()] << OfflineMsg{o["fromUid"].toString(), o["from"].toString(),
                                              o["text"].toString(),
                                              QDateTime::fromString(o["ts"].toString(), Qt::ISODate)};
        }
    }
    for (const QJsonValue& v : root["files"].toArray()) {
        const QJsonObject o = v.toObject();
        m_files << FileMeta{o["chan"].toInt(), o["name"].toString(), o["byUid"].toString(),
                            o["by"].toString(), o["size"].toString().toLongLong(),
                            QDateTime::fromString(o["ts"].toString(), Qt::ISODate)};
    }
}

void ServerCore::loadBansFromJson() {
    m_bans.clear();
    if (m_banFile.isEmpty()) return;
    QFile f(m_banFile);
    if (!f.open(QIODevice::ReadOnly)) return;
    QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
    if (!doc.isArray()) return;
    for (const QJsonValue& v : doc.array()) {
        QJsonObject o = v.toObject();
        BanEntry b;
        b.uid = o["uid"].toString();
        b.ip = o["ip"].toString();
        b.name = o["name"].toString();
        b.reason = o["reason"].toString();
        if (o.contains("expires"))
            b.expires = QDateTime::fromString(o["expires"].toString(), Qt::ISODate);
        m_bans << b;
    }
}

void ServerCore::saveData() {
    saveDataToSql();
}

void ServerCore::saveDataToSql() {
    QSqlDatabase db = QSqlDatabase::database("HallaServerConnection");
    if (!db.isOpen()) {
        log("SQL SAVE ERROR: Database is not open!");
        return;
    }

    db.transaction();
    QSqlQuery q(db);

    bool ok = true;
    ok &= q.exec("DELETE FROM settings");
    ok &= q.exec("DELETE FROM channels");
    ok &= q.exec("DELETE FROM groups");
    ok &= q.exec("DELETE FROM assignments");
    ok &= q.exec("DELETE FROM used_keys");
    ok &= q.exec("DELETE FROM clients");
    ok &= q.exec("DELETE FROM complaints");
    ok &= q.exec("DELETE FROM offline_messages");
    ok &= q.exec("DELETE FROM files");
    if (!ok) {
        log("SQL SAVE ERROR on DELETE: " + q.lastError().text());
    }

    q.prepare("INSERT INTO settings (`key`, `value`) VALUES (:key, :value)");
    q.bindValue(":key", "name"); q.bindValue(":value", m_name); q.exec();
    q.bindValue(":key", "motd"); q.bindValue(":value", m_motd); q.exec();
    if (!m_queryPass.isEmpty()) {
        q.bindValue(":key", "queryPass"); q.bindValue(":value", m_queryPass); q.exec();
    }

    q.prepare("INSERT INTO channels (`id`, `parentId`, `name`, `topic`, `desc`, `password`, `isDefault`, `type`, `moderated`, `codec`, `codecQuality`, `maxClients`, `ntalk`, `bitrate`, `group_perms`, `no_symbol`, `order_index`, `linked_channels`) "
              "VALUES (:id, :parentId, :name, :topic, :desc, :password, :isDefault, :type, :moderated, :codec, :codecQuality, :maxClients, :ntalk, :bitrate, :group_perms, :no_symbol, :order_index, :linked_channels)");
    for (const SvrChan& c : m_channels) {
        if (c.type == 0) continue;
        q.bindValue(":id", c.id);
        q.bindValue(":parentId", c.parent);
        q.bindValue(":name", c.name);
        q.bindValue(":topic", c.topic);
        q.bindValue(":desc", c.desc);
        q.bindValue(":password", c.password);
        q.bindValue(":isDefault", c.def ? 1 : 0);
        q.bindValue(":type", c.type);
        q.bindValue(":moderated", c.moderated ? 1 : 0);
        q.bindValue(":codec", c.codec);
        q.bindValue(":codecQuality", c.quality);
        q.bindValue(":maxClients", c.maxClients);
        q.bindValue(":ntalk", c.ntalk);
        q.bindValue(":bitrate", c.bitrate);
        q.bindValue(":group_perms", QString::fromUtf8(QJsonDocument(c.groupPerms).toJson(QJsonDocument::Compact)));
        q.bindValue(":no_symbol", c.noSymbol ? 1 : 0);
        q.bindValue(":order_index", c.order);
        QJsonArray linked;
        for (int linkedId : c.linkedChannels) linked << linkedId;
        q.bindValue(":linked_channels",
                    QString::fromUtf8(QJsonDocument(linked).toJson(QJsonDocument::Compact)));
        if (!q.exec()) {
            log("SQL SAVE ERROR on channels: " + q.lastError().text());
        }
    }

    q.prepare("INSERT INTO groups (`id`, `name`, `sigla`, `order_index`, `icon`, `perms`) "
              "VALUES (:id, :name, :sigla, :order_index, :icon, :perms)");
    for (const GroupDef& g : m_groups) {
        q.bindValue(":id", g.id);
        q.bindValue(":name", g.name);
        q.bindValue(":sigla", g.sigla);
        q.bindValue(":order_index", g.order);
        q.bindValue(":icon", g.icon);
        q.bindValue(":perms", QString::fromUtf8(QJsonDocument(g.perms).toJson(QJsonDocument::Compact)));
        if (!q.exec()) {
            log("SQL SAVE ERROR on groups: " + q.lastError().text());
        }
    }

    q.prepare("INSERT INTO assignments (`uid`, `groupId`) VALUES (:uid, :groupId)");
    for (auto it = m_assignByUid.begin(); it != m_assignByUid.end(); ++it) {
        q.bindValue(":uid", it.key());
        q.bindValue(":groupId", it.value());
        if (!q.exec()) {
            log(QStringLiteral("SQL SAVE ERROR on assignments (uid=%1, gid=%2): %3")
                .arg(it.key()).arg(QString::number(it.value())).arg(q.lastError().text()));
        }
    }

    q.prepare("INSERT INTO used_keys (`key_val`) VALUES (:key)");
    for (const QString& k : m_usedKeys) {
        q.bindValue(":key", k);
        if (!q.exec()) {
            log("SQL SAVE ERROR on used_keys: " + q.lastError().text());
        }
    }

    q.prepare("INSERT INTO clients (`uid`, `name`, `firstSeen`, `lastSeen`) VALUES (:uid, :name, :first, :last)");
    for (auto it = m_registry.begin(); it != m_registry.end(); ++it) {
        q.bindValue(":uid", it.key());
        q.bindValue(":name", it.value().name);
        q.bindValue(":first", it.value().firstSeen.toString(Qt::ISODate));
        q.bindValue(":last", it.value().lastSeen.toString(Qt::ISODate));
        if (!q.exec()) {
            log("SQL SAVE ERROR on clients: " + q.lastError().text());
        }
    }

    q.prepare("INSERT INTO complaints (`uid`, `name`, `byUid`, `byName`, `text`, `ts`) VALUES (:uid, :name, :byUid, :byName, :text, :ts)");
    for (const Complaint& cp : m_complaints) {
        q.bindValue(":uid", cp.uid);
        q.bindValue(":name", cp.name);
        q.bindValue(":byUid", cp.byUid);
        q.bindValue(":byName", cp.byName);
        q.bindValue(":text", cp.text);
        q.bindValue(":ts", cp.ts.toString(Qt::ISODate));
        if (!q.exec()) {
            log("SQL SAVE ERROR on complaints: " + q.lastError().text());
        }
    }

    q.prepare("INSERT INTO offline_messages (`targetUid`, `fromUid`, `fromName`, `text`, `ts`) VALUES (:targetUid, :fromUid, :fromName, :text, :ts)");
    for (auto it = m_offline.begin(); it != m_offline.end(); ++it) {
        for (const OfflineMsg& om : it.value()) {
            q.bindValue(":targetUid", it.key());
            q.bindValue(":fromUid", om.fromUid);
            q.bindValue(":fromName", om.fromName);
            q.bindValue(":text", om.text);
            q.bindValue(":ts", om.ts.toString(Qt::ISODate));
            if (!q.exec()) {
                log("SQL SAVE ERROR on offline_messages: " + q.lastError().text());
            }
        }
    }

    q.prepare("INSERT INTO files (`chanId`, `name`, `byUid`, `byName`, `size`, `ts`) VALUES (:chanId, :name, :byUid, :byName, :size, :ts)");
    for (const FileMeta& fm : m_files) {
        q.bindValue(":chanId", fm.chan);
        q.bindValue(":name", fm.name);
        q.bindValue(":byUid", fm.byUid);
        q.bindValue(":byName", fm.by);
        q.bindValue(":size", fm.size);
        q.bindValue(":ts", fm.ts.toString(Qt::ISODate));
        if (!q.exec()) {
            log("SQL SAVE ERROR on files: " + q.lastError().text());
        }
    }

    if (!db.commit()) {
        log("SQL SAVE TRANSACTION COMMIT FAILED: " + db.lastError().text());
    } else {
        log("DEBUG: saveDataToSql concluído com sucesso e commitado!");
    }
}

void ServerCore::loadBans() {
    m_bans.clear();
    
    QSqlDatabase db = QSqlDatabase::database("HallaServerConnection");
    if (!db.isOpen()) return;

    QSqlQuery q(db);
    if (q.exec("SELECT uid, ip, name, reason, expires FROM bans")) {
        while (q.next()) {
            BanEntry b;
            b.uid = q.value(0).toString();
            b.ip = q.value(1).toString();
            b.name = q.value(2).toString();
            b.reason = q.value(3).toString();
            QString exp = q.value(4).toString();
            if (!exp.isEmpty()) {
                b.expires = QDateTime::fromString(exp, Qt::ISODate);
            }
            m_bans << b;
        }
    }
}

void ServerCore::saveBans() {
    saveBansToSql();
}

void ServerCore::saveBansToSql() {
    QSqlDatabase db = QSqlDatabase::database("HallaServerConnection");
    if (!db.isOpen()) return;

    db.transaction();
    QSqlQuery q(db);
    q.exec("DELETE FROM bans");
    q.prepare("INSERT INTO bans (`uid`, `ip`, `name`, `reason`, `expires`) VALUES (:uid, :ip, :name, :reason, :expires)");
    for (const BanEntry& b : m_bans) {
        q.bindValue(":uid", b.uid);
        q.bindValue(":ip", b.ip);
        q.bindValue(":name", b.name);
        q.bindValue(":reason", b.reason);
        q.bindValue(":expires", b.expires.isValid() ? b.expires.toString(Qt::ISODate) : QString());
        q.exec();
    }
    db.commit();
}
void ServerCore::setPrivilegeKeys(const QStringList& keys) {
    m_privKeyGroup.clear();
    for (QString k : keys) {
        k = k.trimmed();
        if (k.isEmpty()) continue;
        // formato: CHAVE ou CHAVE@grupo
        const int at = k.indexOf('@');
        if (at > 0)
            m_privKeyGroup[k.left(at)] = k.mid(at + 1);
        else
            m_privKeyGroup[k] = QStringLiteral("admin");
    }
}

// ==================================================================== conexões
void ServerCore::onNewConnection() {
    while (m_tcp->hasPendingConnections()) {
        QTcpSocket* s = m_tcp->nextPendingConnection();
        ClientSession* c = new ClientSession(s, this, this);
        connect(c, &ClientSession::messageReceived, this, &ServerCore::onClientMessage);
        connect(c, &ClientSession::disconnected, this, &ServerCore::onClientDisconnected);
        log(QStringLiteral("Nova conexão de %1").arg(s->peerAddress().toString()));
    }
}

void ServerCore::onClientDisconnected(ClientSession* client) {
    if (!client) return;
    if (client->id() > 0 && m_clients.contains(client->id())) {
        QJsonObject left = HProto::msg("user_left");
        left["id"] = client->id();
        left["reason"] = "dropped";
        broadcast(left, client->id());
        removeFromChannels(client->id());
        m_clients.remove(client->id());
        if (client->voiceToken()) m_byVoiceToken.remove(client->voiceToken());
        log(QStringLiteral("Cliente #%1 (%2) desconectou").arg(client->id()).arg(client->name()));
    }
    client->deleteLater();
}

void ServerCore::checkIdleClients() {
    // limpa canais temporários vazios
    QList<int> toRemove;
    for (const SvrChan& c : m_channels)
        if (c.type == 0 && c.users.isEmpty()) toRemove << c.id;
    QList<int> linkAffected;
    for (int id : toRemove) {
        m_channels.remove(id);
        for (SvrChan& other : m_channels) {
            if (other.linkedChannels.removeAll(id) > 0 && !linkAffected.contains(other.id))
                linkAffected << other.id;
        }
        QJsonObject m = HProto::msg("chan_removed");
        m["id"] = id;
        broadcast(m);
    }
    for (int affectedId : linkAffected) {
        if (!m_channels.contains(affectedId)) continue;
        QJsonObject update = HProto::msg("chan_update");
        update["chan"] = chanToJson(m_channels[affectedId]);
        broadcast(update);
    }
    if (!toRemove.isEmpty()) saveData();
}

void ServerCore::registerClient(ClientSession* c) {
    if (c->uniqueId().isEmpty()) return;
    RegClient& rc = m_registry[c->uniqueId()];
    if (!rc.firstSeen.isValid()) rc.firstSeen = QDateTime::currentDateTime();
    rc.name = c->name();
    rc.lastSeen = QDateTime::currentDateTime();
    saveData();
}

// ==================================================================== mensagens
void ServerCore::onClientMessage(ClientSession* c, const QJsonObject& obj) {
    const QString t = obj["t"].toString();

    // Consulta leve usada pela tela inicial do Mobile. Não cria uma sessão,
    // não consome vaga e permite mostrar o limite configurado no servidor
    // antes de o usuário tocar no cartão para entrar.
    if (c->id() == 0 && t == "server_probe") {
        QJsonObject response = HProto::msg("server_probe");
        QJsonObject server;
        server["name"] = m_name;
        server["motd"] = m_motd;
        server["ver"] = m_version;
        server["maxClients"] = m_maxClients;
        response["server"] = server;
        response["clients"] = m_clients.size();
        response["maxClients"] = m_maxClients;
        c->send(response);
        c->closeAndDelete();
        return;
    }

    if (c->id() == 0 && t != "hello") return; // exige login antes de tudo

    if (t == "hello")           handleHello(c, obj);
    else if (t == "ping")        { QJsonObject p = HProto::msg("pong"); p["ts"] = obj["ts"]; c->send(p); }
    else if (t == "chat")        handleChat(c, obj);
    else if (t == "move")        handleMove(c, obj);
    else if (t == "move_other")  handleMoveOther(c, obj);
    else if (t == "commander")    handleCommander(c, obj);
    else if (t == "voice_hello") {
        if (!c->voiceToken()) {
            c->setVoiceToken(m_nextToken++);
            m_byVoiceToken[c->voiceToken()] = c;
        }
        QJsonObject v = HProto::msg("voice_token");
        v["token"] = QString::number(c->voiceToken());
        v["udp"] = m_voice ? m_voice->port() : 0;
        c->send(v);
    }
    else if (t == "talking")     handleTalking(c, obj);
    else if (t == "status")      handleStatus(c, obj);
    else if (t == "nick")        handleNick(c, obj);
    else if (t == "desc")        handleDesc(c, obj);
    else if (t == "poke")        handlePoke(c, obj);
    else if (t == "chan_create") handleChanCreate(c, obj);
    else if (t == "chan_edit")   handleChanEdit(c, obj);
    else if (t == "chan_move")   handleChanMove(c, obj);
    else if (t == "chan_link")   handleChanLink(c, obj);
    else if (t == "chan_delete") handleChanDelete(c, obj);
    else if (t == "kick")        handleKick(c, obj);
    else if (t == "ban")         handleBan(c, obj);
    else if (t == "banlist")     handleBanList(c);
    else if (t == "unban")       handleUnban(c, obj);
    else if (t == "privkey")     handlePrivkey(c, obj);
    else if (t == "volume")      handleVolume(c, obj);
    else if (t == "group_list")  handleGroupList(c);
    else if (t == "group_set")   handleGroupSet(c, obj);
    else if (t == "group_delete") handleGroupDelete(c, obj);
    else if (t == "client_set_group") handleClientSetGroup(c, obj);
    else if (t == "server_edit") handleServerEdit(c, obj);
    else if (t == "avatar_set")     handleAvatarSet(c, obj);
    else if (t == "avatar_get")     handleAvatarGet(c, obj);
    else if (t == "icon_get")       handleIconGet(c, obj);
    else if (t == "icon_set")       handleIconSet(c, obj);
    else if (t == "offline_send")   handleOfflineSend(c, obj);
    else if (t == "complaint_add")  handleComplaintAdd(c, obj);
    else if (t == "complaint_list") handleComplaintList(c);
    else if (t == "complaint_clear") handleComplaintClear(c, obj);
    else if (t == "whisper")        handleWhisper(c, obj);
    else if (t == "ft_upload")      handleFtUpload(c, obj);
    else if (t == "ft_list")        handleFtList(c, obj);
    else if (t == "ft_download")    handleFtDownload(c, obj);
    else if (t == "ft_delete")      handleFtDelete(c, obj);
    else if (t == "quit") {
        // desconexão graciosa: notifica os demais antes de fechar
        QJsonObject left = HProto::msg("user_left");
        left["id"] = c->id();
        left["reason"] = "quit";
        broadcast(left, c->id());
        removeFromChannels(c->id());
        m_clients.remove(c->id());
        if (c->voiceToken()) m_byVoiceToken.remove(c->voiceToken());
        log(QStringLiteral("Cliente #%1 (%2) saiu").arg(c->id()).arg(c->name()));
        c->closeAndDelete();
    }
}

void ServerCore::handleHello(ClientSession* c, const QJsonObject& obj) {
    if (c->id() != 0) return; // já logado

    const QString nick = obj["nick"].toString().trimmed().left(30);
    const QString uid = obj["uid"].toString().left(64);
    const QString pass = obj["pass"].toString();
    const QString adminPass = obj["adminPass"].toString();
    const int clientProto = obj["proto"].toInt();

    if (clientProto < HProto::kProtoMin || clientProto > HProto::kProtoVersion) {
        sendError(c, "bad_proto",
                  QStringLiteral("Versão do protocolo incompatível (servidor aceita v%1-v%2)")
                      .arg(HProto::kProtoMin).arg(HProto::kProtoVersion));
        c->closeAndDelete();
        return;
    }
    if (nick.isEmpty()) {
        sendError(c, "bad_nick", "Apelido inválido");
        c->closeAndDelete();
        return;
    }
    if (uid.isEmpty()) {
        sendError(c, "bad_uid", "Identidade (ID único) ausente — atualize o cliente");
        c->closeAndDelete();
        return;
    }

    // banido? (por UID ou por IP)
    const QString ip = c->ip().toString();
    for (const BanEntry& b : m_bans) {
        const bool match = (!b.uid.isEmpty() && b.uid == uid)
                        || (!b.ip.isEmpty() && b.ip == ip);
        if (match && (!b.expires.isValid() || b.expires > QDateTime::currentDateTime())) {
            sendError(c, "banned",
                      b.reason.isEmpty() ? QStringLiteral("Você está banido deste servidor")
                                         : QStringLiteral("Banido: %1").arg(b.reason));
            c->closeAndDelete();
            return;
        }
    }

    // servidor cheio
    if (m_clients.size() >= m_maxClients) {
        sendError(c, "server_full", "Servidor cheio");
        c->closeAndDelete();
        return;
    }

    // senha do servidor
    if (!m_password.isEmpty() && pass != m_password) {
        sendError(c, "bad_password", "Senha do servidor incorreta");
        c->closeAndDelete();
        return;
    }

    // apelido duplicado
    for (ClientSession* other : m_clients)
        if (other->name().compare(nick, Qt::CaseInsensitive) == 0) {
            sendError(c, "name_in_use", "Apelido já em uso");
            c->closeAndDelete();
            return;
        }

    c->setId(m_nextId++);
    c->setName(nick);
    c->setUid(uid);
    c->setVersion(obj["ver"].toString().left(20));
    c->setPlatform(obj["platform"].toString().left(20));

    // grupo: atribuição persistente por UID tem prioridade; senão "normal"
    int gid = m_assignByUid.value(uid, 0);
    log(QStringLiteral("DEBUG: Cliente \"%1\" com UID \"%2\" conectando. GID mapeado recuperado: %3")
            .arg(nick, uid, QString::number(gid)));
    if (!m_groups.contains(gid)) gid = 2; // normal
    applyGroup(c, gid, false);
    // senha de administrador eleva a admin (mesmo com atribuição salva)
    if (!adminPass.isEmpty() && adminPass == m_adminPassword && !m_adminPassword.isEmpty())
        applyGroup(c, 3, false);

    m_clients[c->id()] = c;
    addToChannel(c->id(), 1); // entra no canal padrão
    log(QStringLiteral("Cliente #%1 (%2) entrou [grupo: %3]")
            .arg(c->id()).arg(nick, c->group()));

    c->setAvatarHash(m_avatarHash.value(uid)); // v3: avatar salvo
    sendWelcome(c);
    registerClient(c);

    // v3: entrega mensagens offline pendentes
    if (m_offline.contains(uid) && !m_offline[uid].isEmpty()) {
        for (const OfflineMsg& om : m_offline[uid]) {
            QJsonObject m = HProto::msg("offline_msg");
            m["fromUid"] = om.fromUid;
            m["fromName"] = om.fromName;
            m["text"] = om.text;
            m["ts"] = om.ts.toString(Qt::ISODate);
            c->send(m);
        }
        m_offline.remove(uid);
        saveData();
    }

    QJsonObject joined = HProto::msg("user_joined");
    joined["user"] = c->toJson();
    broadcast(joined, c->id());

    // v3: Envia uma sinalização explícita de movimento para o canal padrão (1) 
    // para que todos os outros clientes saibam onde colocar o novo usuário na árvore.
    QJsonObject moved = HProto::msg("user_moved");
    moved["id"] = c->id();
    moved["channel"] = 1;
    broadcast(moved);
}

void ServerCore::sendWelcome(ClientSession* c) {
    QJsonObject w = HProto::msg("welcome");
    w["selfId"] = c->id();
    w["proto"] = HProto::kProtoVersion;

    QJsonObject server;
    server["name"] = m_name;
    server["motd"] = m_motd;
    server["ver"] = m_version;
#ifdef Q_OS_WIN
    server["platform"] = "Windows";
#else
    server["platform"] = "Linux";
#endif
    server["maxClients"] = m_maxClients;
    if (!m_serverBanner.isEmpty())
        server["banner"] = QString::fromLatin1(m_serverBanner.toBase64());
    w["server"] = server;

    QJsonArray users;
    for (ClientSession* o : m_clients) users << o->toJson();
    w["users"] = users;

    QJsonArray chans;
    for (const SvrChan& ch : m_channels) chans << chanToJson(ch);
    w["channels"] = chans;

    // v2: lista de grupos + minhas permissões
    QJsonArray groups;
    for (const GroupDef& g : m_groups) groups << groupToJson(g);
    w["groups"] = groups;
    w["myPerms"] = myPermsOf(m_groups.value(c->groupId(), m_groups.value(1)));

    if (!c->voiceToken()) {
        c->setVoiceToken(m_nextToken++);
        m_byVoiceToken[c->voiceToken()] = c;
    }
    QJsonObject voice;
    voice["udp"] = m_voice ? m_voice->port() : 0;
    voice["token"] = QString::number(c->voiceToken());
    w["voice"] = voice;

    c->send(w);
}

void ServerCore::handleChat(ClientSession* c, const QJsonObject& obj) {
    const QString scope = obj["scope"].toString();
    const QString text = obj["text"].toString().left(1024);
    if (text.trimmed().isEmpty()) return;
    if (scope == "private" && !hasPerm(c, "privmsg")) {
        sendError(c, "no_permission", "Sem permissão para mensagens privadas");
        return;
    }

    QJsonObject m = HProto::msg("chat");
    m["scope"] = scope;
    m["from"] = c->id();
    m["fromName"] = c->name();
    m["text"] = text;

    if (scope == "server")         broadcast(m);
    else if (scope == "channel") {
        const int chan = channelOfUser(c->id());
        if (!hasChannelPerm(c, chan, "text_chat")) {
            sendError(c, "no_permission", "Sem permissão para enviar chat de texto neste canal");
            return;
        }
        for (ClientSession* o : m_clients)
            if (channelOfUser(o->id()) == chan) o->send(m);
    } else if (scope == "private") {
        const int to = obj["to"].toInt();
        if (m_clients.contains(to)) {
            m["to"] = to;
            m_clients[to]->send(m);
            c->send(m); // eco para o remetente
        }
    }
}

void ServerCore::handleMove(ClientSession* c, const QJsonObject& obj) {
    const int target = obj["channel"].toInt();
    if (target <= 0 || !m_channels.contains(target)) {
        sendError(c, "invalid_channel", "Você só pode se mover para um canal existente");
        return;
    }

    if (!hasChannelPerm(c, target, "join")) {
        sendError(c, "no_permission", "Sem permissão para entrar neste canal");
        return;
    }

    SvrChan& ch = m_channels[target];
    const int oldChan = channelOfUser(c->id());
    if (oldChan == target) return;

    if (ch.maxClients >= 0 && ch.users.size() >= ch.maxClients) {
        sendError(c, "channel_full",
                  QStringLiteral("O canal \"%1\" está cheio").arg(ch.name));
        return;
    }
    if (!ch.password.isEmpty() && !hasPerm(c, "ignoreChanPass")
            && obj["pass"].toString() != ch.password) {
        sendError(c, "bad_channel_pass", "Senha do canal incorreta");
        return;
    }

    removeFromChannels(c->id());
    ch.users << c->id();

    QJsonObject m = HProto::msg("user_moved");
    m["id"] = c->id();
    m["channel"] = target;
    m["by"] = c->id();
    broadcast(m);
}

void ServerCore::handleMoveOther(ClientSession* c, const QJsonObject& obj) {
    if (!hasPerm(c, "move") && !hasPerm(c, "i_client_move_power")) {
        sendError(c, "no_permission", "Sem permissão para mover clientes");
        return;
    }
    const int id = obj["id"].toInt();
    const int target = obj["channel"].toInt();
    if (target <= 0 || !m_clients.contains(id) || !m_channels.contains(target)) {
        sendError(c, "invalid_channel", "O destino precisa ser um canal existente");
        return;
    }
    if (!hasChannelPerm(c, target, QStringLiteral("move"))) {
        sendError(c, "no_permission", "Sem permissão para mover clientes para este canal");
        return;
    }
    removeFromChannels(id);
    m_channels[target].users << id;
    QJsonObject m = HProto::msg("user_moved");
    m["id"] = id; m["channel"] = target; m["by"] = c->id();
    broadcast(m);
}

void ServerCore::handleCommander(ClientSession* c, const QJsonObject& obj) {
    const int targetId = obj["id"].toInt(c->id());
    const bool on = obj["on"].toBool();
    if (!m_clients.contains(targetId)) return;

    const bool selfPower = hasPerm(c, "selfCommander")
        || hasPerm(c, "b_client_is_channel_commander")
        || hasPerm(c, "setCommander")
        || hasPerm(c, "b_client_set_channel_commander");
    const bool otherPower = hasPerm(c, "setCommander")
        || hasPerm(c, "b_client_set_channel_commander");
    const bool allowed = targetId == c->id() ? selfPower : otherPower;
    if (!allowed) {
        sendError(c, "no_permission",
                  targetId == c->id()
                      ? "Sem permissão para ser comandante do canal"
                      : "Sem permissão para definir o comandante de outro cliente");
        return;
    }

    // O comando continua sendo uma ação de servidor, não um estado local
    // falsificável enviado em "status". A mudança é refletida para todos.
    ClientSession* target = m_clients.value(targetId);
    target->setCommander(on);
    QJsonObject u = HProto::msg("user_state");
    u["id"] = targetId;
    u["cc"] = on;
    u["by"] = c->id();
    broadcast(u);
}

void ServerCore::handleTalking(ClientSession* c, const QJsonObject& obj) {
    const bool on = obj["on"].toBool();
    if (on && !canTalkIn(c, channelOfUser(c->id()))) {
        sendError(c, "no_talk_power",
                  "Você não tem poder de fala suficiente neste canal");
        return; // não propaga: ninguém vê o indicador de fala
    }
    if (c->talking() != on) {
        c->setTalking(on);
        QJsonObject u = HProto::msg("user_state");
        u["id"] = c->id();
        u["talking"] = on;
        u["whispering"] = (on && !c->whisperIds().isEmpty());
        broadcast(u, c->id());
    }
}

bool ServerCore::canTalkIn(const ClientSession* c, int channelId) const {
    if (!m_channels.contains(channelId)) return false;
    if (!hasChannelPerm(c, channelId, "talk")) return false;
    const SvrChan& ch = m_channels[channelId];
    int need = ch.ntalk;
    if (need <= 0 && ch.moderated) need = 25;
    if (need <= 0) return true;
    if (hasPerm(c, "ignoreTalkPower")) return true;
    return talkPower(c) >= need;
}

void ServerCore::handleStatus(ClientSession* c, const QJsonObject& obj) {
    if (obj.contains("mic"))  c->setMicMuted(obj["mic"].toBool());
    if (obj.contains("spk"))  c->setSpkMuted(obj["spk"].toBool());
    if (obj.contains("away")) c->setAway(obj["away"].toBool());
    if (obj.contains("rec"))  c->setRecording(obj["rec"].toBool());
    if (obj.contains("cc")) {
        const bool requested = obj["cc"].toBool();
        const bool selfPower = hasPerm(c, "selfCommander")
            || hasPerm(c, "b_client_is_channel_commander")
            || hasPerm(c, "setCommander")
            || hasPerm(c, "b_client_set_channel_commander");
        if (!requested || selfPower) {
            c->setCommander(requested);
        } else {
            sendError(c, "no_permission", "Sem permissão para ser comandante do canal");
        }
    }

    QJsonObject u = HProto::msg("user_state");
    u["id"] = c->id();
    u["mic"] = c->micMuted();
    u["spk"] = c->spkMuted();
    u["away"] = c->away();
    u["rec"] = c->recording();
    u["cc"] = c->commander();
    broadcast(u);
}

void ServerCore::handleNick(ClientSession* c, const QJsonObject& obj) {
    const QString name = obj["name"].toString().trimmed().left(30);
    if (name.isEmpty() || name == c->name()) return;
    for (ClientSession* other : m_clients)
        if (other != c && other->name().compare(name, Qt::CaseInsensitive) == 0) {
            sendError(c, "name_in_use", "Apelido já em uso");
            return;
        }
    c->setName(name);
    if (!c->uniqueId().isEmpty() && m_registry.contains(c->uniqueId()))
        m_registry[c->uniqueId()].name = name;
    QJsonObject m = HProto::msg("user_nick");
    m["id"] = c->id();
    m["name"] = name;
    broadcast(m);
}

void ServerCore::handleDesc(ClientSession* c, const QJsonObject& obj) {
    c->setDescription(obj["text"].toString().left(200));
    QJsonObject m = HProto::msg("user_desc");
    m["id"] = c->id();
    m["text"] = c->description();
    broadcast(m);
}

void ServerCore::handlePoke(ClientSession* c, const QJsonObject& obj) {
    if (!hasPerm(c, "poke")) {
        sendError(c, "no_permission", "Sem permissão para cutucar");
        return;
    }
    const int to = obj["to"].toInt();
    if (!m_clients.contains(to)) return;
    QJsonObject m = HProto::msg("poke");
    m["from"] = c->id();
    m["fromName"] = c->name();
    m["msg"] = obj["msg"].toString().left(100);
    m_clients[to]->send(m);
    c->send(m); // eco
}

void ServerCore::handleVolume(ClientSession*, const QJsonObject&) {
    // volume local — o cliente aplica localmente; nada a fazer no servidor
}

void ServerCore::handleChanCreate(ClientSession* c, const QJsonObject& obj) {
    const int type = obj["type"].toInt(2);
    // permissão granular por tipo de canal
    const char* perm = (type == 0) ? "chanCreateTemp"
                     : (type == 1) ? "chanCreateSemi" : "chanCreatePerm";
    if (!hasPerm(c, perm)) {
        sendError(c, "no_permission",
                  QStringLiteral("Sem permissão para criar canais do tipo %1")
                      .arg(type == 0 ? "temporário" : (type == 1 ? "semi-permanente" : "permanente")));
        return;
    }

    const QString name = obj["name"].toString().trimmed();
    if (name.isEmpty()) return;

    SvrChan ch;
    ch.id = m_nextChanId++;
    ch.parent = obj["parent"].toInt(0);
    if (ch.parent != 0 && !m_channels.contains(ch.parent)) ch.parent = 0;
    if (ch.parent != 0 && !hasChannelPerm(c, ch.parent, QStringLiteral("channel_create"))) {
        sendError(c, "no_permission", "Sem permissão para criar canais neste canal");
        return;
    }
    if (ch.parent != 0 && type == 0
            && !hasChannelPerm(c, ch.parent, QStringLiteral("chan_create_temp"))) {
        sendError(c, "no_permission", "Sem permissão para criar canais temporários aqui");
        return;
    }
    ch.name = name;
    ch.noSymbol = obj["noSymbol"].toBool(false);
    if (obj.contains("order")) {
        ch.order = qMax(0, obj["order"].toInt());
    } else {
        for (const SvrChan& sibling : m_channels)
            if (sibling.parent == ch.parent) ch.order = qMax(ch.order, sibling.order + 10);
    }
    ch.topic = obj["topic"].toString().left(80);
    ch.desc = obj["desc"].toString();
    ch.password = obj["pass"].toString();
    ch.def = false;
    ch.moderated = obj["moderated"].toBool(false);
    ch.ntalk = qBound(0, obj["ntalk"].toInt(0), 100);
    ch.type = type;
    ch.codec = qBound(0, obj["codec"].toInt(4), 5);
    ch.quality = qBound(0, obj["quality"].toInt(6), 10);
    ch.bitrate = qBound(16, obj["bitrate"].toInt(96), 384);
    if (obj.contains("groupPerms")) ch.groupPerms = obj["groupPerms"].toObject();
    ch.maxClients = obj["max"].toInt(-1);
    ch.ops << c->uniqueId(); // v3: criador vira operador do canal
    m_channels[ch.id] = ch;
    saveData();

    QJsonObject m = HProto::msg("chan_update");
    m["chan"] = chanToJson(ch);
    broadcast(m);
}

void ServerCore::handleChanMove(ClientSession* c, const QJsonObject& obj) {
    const int id = obj["id"].toInt();
    const int parent = obj["parent"].toInt(0);
    if (!m_channels.contains(id) || id == 1) return;
    if (parent != 0 && !m_channels.contains(parent)) return;
    if (!hasPerm(c, "chanEdit") && !isChanOp(c, id)) {
        sendError(c, "no_permission", "Sem permissão para reordenar canais");
        return;
    }
    // Impede colocar um canal dentro de si mesmo ou de um descendente.
    for (int p = parent; p != 0 && m_channels.contains(p); p = m_channels[p].parent) {
        if (p == id) {
            sendError(c, "invalid_parent", "Um canal não pode ser colocado dentro de sua própria árvore");
            return;
        }
    }

    QList<int> siblings;
    for (const SvrChan& sibling : m_channels)
        if (sibling.parent == parent && sibling.id != id) siblings << sibling.id;
    std::sort(siblings.begin(), siblings.end(), [&](int a, int b) {
        if (m_channels[a].order != m_channels[b].order)
            return m_channels[a].order < m_channels[b].order;
        return m_channels[a].name.localeAwareCompare(m_channels[b].name) < 0;
    });
    const int position = qBound(0, obj["order"].toInt(siblings.size()), siblings.size());
    siblings.insert(position, id);
    for (int i = 0; i < siblings.size(); ++i) {
        m_channels[siblings[i]].parent = parent;
        m_channels[siblings[i]].order = i * 10;
    }
    saveData();
    for (int siblingId : siblings) {
        QJsonObject m = HProto::msg("chan_update");
        m["chan"] = chanToJson(m_channels[siblingId]);
        broadcast(m);
    }
}

void ServerCore::handleChanLink(ClientSession* c, const QJsonObject& obj) {
    QList<int> ids;
    QSet<int> seen;
    for (const QJsonValue& value : obj["ids"].toArray()) {
        const int id = value.toInt();
        if (id > 0 && !seen.contains(id)) {
            seen.insert(id);
            ids << id;
        }
    }
    if (ids.size() < 2) {
        sendError(c, "invalid_channels", "Selecione pelo menos dois canais para vincular");
        return;
    }
    for (int id : ids) {
        if (!m_channels.contains(id)) {
            sendError(c, "invalid_channel", "Um dos canais selecionados não existe mais");
            return;
        }
    }

    // Vincular canais altera a rota de áudio de cada canal. A permissão
    // existente de edição de canal é usada; operadores só podem fazer isso
    // quando controlam todos os canais selecionados (e não o canal padrão).
    bool operatorOfAll = true;
    for (int id : ids) {
        if (id == 1 || !isChanOp(c, id)) {
            operatorOfAll = false;
            break;
        }
    }
    if (!hasPerm(c, "chanEdit") && !operatorOfAll) {
        sendError(c, "no_permission", "Sem permissão para vincular canais");
        return;
    }

    const bool link = obj.contains("link") ? obj["link"].toBool() : true;
    for (int i = 0; i < ids.size(); ++i) {
        for (int j = i + 1; j < ids.size(); ++j) {
            SvrChan& a = m_channels[ids[i]];
            SvrChan& b = m_channels[ids[j]];
            if (link) {
                if (!a.linkedChannels.contains(b.id)) a.linkedChannels << b.id;
                if (!b.linkedChannels.contains(a.id)) b.linkedChannels << a.id;
            } else {
                a.linkedChannels.removeAll(b.id);
                b.linkedChannels.removeAll(a.id);
            }
        }
    }

    saveData();
    for (int id : ids) {
        QJsonObject update = HProto::msg("chan_update");
        update["chan"] = chanToJson(m_channels[id]);
        broadcast(update);
    }
    log(QStringLiteral("Canais %1 %2 foram %3")
            .arg(ids.size())
            .arg(link ? QStringLiteral("vinculados") : QStringLiteral("desvinculados"))
            .arg(c->name()));
}

void ServerCore::handleChanEdit(ClientSession* c, const QJsonObject& obj) {
    const int id = obj["id"].toInt();
    if (!m_channels.contains(id)) return;
    // v3: operador do canal pode editar o próprio canal (exceto o padrão)
    if (!hasPerm(c, "chanEdit") && !(id != 1 && isChanOp(c, id))) {
        sendError(c, "no_permission", "Sem permissão para editar canais");
        return;
    }
    // operadores de canal podem promover/rebaixar outros operadores (por UID)
    if (obj.contains("op_add") || obj.contains("op_del")) {
        if (!hasPerm(c, "chanEdit") && !isChanOp(c, id)) {
            sendError(c, "no_permission", "Sem permissão para gerenciar operadores");
            return;
        }
        const QString targetUid = obj["uid"].toString();
        SvrChan& chan = m_channels[id];
        if (obj.contains("op_add") && !targetUid.isEmpty() && !chan.ops.contains(targetUid))
            chan.ops << targetUid;
        if (obj.contains("op_del")) chan.ops.removeAll(targetUid);
        saveData();
        QJsonObject m = HProto::msg("chan_update");
        m["chan"] = chanToJson(chan);
        broadcast(m);
        return;
    }
    SvrChan& ch = m_channels[id];
    if (obj.contains("name")) ch.name = obj["name"].toString().trimmed();
    if (obj.contains("noSymbol")) ch.noSymbol = obj["noSymbol"].toBool();
    if (obj.contains("topic")) ch.topic = obj["topic"].toString().left(80);
    if (obj.contains("desc")) ch.desc = obj["desc"].toString();
    if (obj.contains("pass")) ch.password = obj["pass"].toString();
    if (obj.contains("moderated")) ch.moderated = obj["moderated"].toBool();
    if (obj.contains("ntalk")) ch.ntalk = qBound(0, obj["ntalk"].toInt(), 100);
    if (obj.contains("type") && id != 1) ch.type = obj["type"].toInt();
    if (obj.contains("codec")) ch.codec = qBound(0, obj["codec"].toInt(), 5);
    if (obj.contains("quality")) ch.quality = qBound(0, obj["quality"].toInt(), 10);
    if (obj.contains("bitrate")) ch.bitrate = qBound(16, obj["bitrate"].toInt(96), 384);
    if (obj.contains("groupPerms")) ch.groupPerms = obj["groupPerms"].toObject();
    if (obj.contains("max")) ch.maxClients = obj["max"].toInt();
    saveData();

    QJsonObject m = HProto::msg("chan_update");
    m["chan"] = chanToJson(ch);
    broadcast(m);
}

void ServerCore::handleChanDelete(ClientSession* c, const QJsonObject& obj) {
    const int id = obj["id"].toInt();
    if (!m_channels.contains(id) || id == 1) return;
    if (!hasPerm(c, "chanDelete")) {
        sendError(c, "no_permission", "Sem permissão para excluir canais");
        return;
    }
    // sub-canais impedem exclusão
    for (const SvrChan& ch : m_channels)
        if (ch.parent == id) {
            sendError(c, "has_children", "Exclua primeiro os sub-canais");
            return;
        }
    // move usuários para o padrão
    for (int uid : m_channels[id].users) {
        removeFromChannels(uid);
        m_channels[1].users << uid;
        QJsonObject m = HProto::msg("user_moved");
        m["id"] = uid; m["channel"] = 1; m["by"] = 0;
        broadcast(m);
    }
    m_channels.remove(id);
    QList<int> linkAffected;
    for (SvrChan& other : m_channels) {
        if (other.linkedChannels.removeAll(id) > 0) linkAffected << other.id;
    }
    removeChannelFiles(id); // v3: apaga arquivos do canal
    saveData();
    QJsonObject m = HProto::msg("chan_removed");
    m["id"] = id;
    broadcast(m);
    for (int affectedId : linkAffected) {
        QJsonObject update = HProto::msg("chan_update");
        update["chan"] = chanToJson(m_channels[affectedId]);
        broadcast(update);
    }
}

void ServerCore::handleKick(ClientSession* c, const QJsonObject& obj) {
    const int id = obj["id"].toInt();
    const bool fromServer = obj["from"].toString() == "server";
    // v3: kick de CANAL também é permitido ao operador do canal da vítima
    const bool chanKickByOp = !fromServer && m_clients.contains(id)
                              && isChanOp(c, channelOfUser(id));
    if (!hasPerm(c, "kick") && !chanKickByOp) {
        sendError(c, "no_permission", "Sem permissão para expulsar");
        return;
    }
    if (!m_clients.contains(id) || id == c->id()) return;
    // operador não expulsa outro operador do mesmo canal
    if (chanKickByOp && !hasPerm(c, "kick")
            && m_channels[channelOfUser(id)].ops.contains(m_clients[id]->uniqueId())) {
        sendError(c, "no_permission", "Você não pode expulsar outro operador");
        return;
    }
    // não-administrador supremo não expulsa administrador supremo
    if (!hasPerm(c, "*") && hasPerm(m_clients[id], "*")) {
        sendError(c, "no_permission", "Você não pode expulsar este cliente");
        return;
    }
    doKick(m_clients[id], obj["reason"].toString(), fromServer, false);
}

void ServerCore::handleBan(ClientSession* c, const QJsonObject& obj) {
    if (!hasPerm(c, "ban")) {
        sendError(c, "no_permission", "Sem permissão para banir");
        return;
    }
    const int id = obj["id"].toInt();
    if (!m_clients.contains(id) || id == c->id()) return;
    if (!hasPerm(c, "*") && hasPerm(m_clients[id], "*")) {
        sendError(c, "no_permission", "Você não pode banir este cliente");
        return;
    }
    const int minutes = obj["minutes"].toInt(0);

    BanEntry b;
    b.uid = m_clients[id]->uniqueId();
    b.ip = m_clients[id]->ip().toString();
    b.name = m_clients[id]->name();
    b.reason = obj["reason"].toString();
    if (minutes > 0) b.expires = QDateTime::currentDateTime().addSecs(qint64(minutes) * 60);
    m_bans << b;
    saveBans();

    doKick(m_clients[id], b.reason, true, true, minutes);
}

void ServerCore::handleBanList(ClientSession* c) {
    if (!hasPerm(c, "banList")) {
        sendError(c, "no_permission", "Sem permissão para ver a lista de banidos");
        return;
    }
    QJsonObject m = HProto::msg("banlist");
    QJsonArray arr;
    for (const BanEntry& b : m_bans) {
        QJsonObject o;
        o["uid"] = b.uid; o["ip"] = b.ip; o["name"] = b.name; o["reason"] = b.reason;
        if (b.expires.isValid()) o["expires"] = b.expires.toString(Qt::ISODate);
        arr << o;
    }
    m["bans"] = arr;
    c->send(m);
}

void ServerCore::handleUnban(ClientSession* c, const QJsonObject& obj) {
    if (!hasPerm(c, "ban")) {
        sendError(c, "no_permission", "Sem permissão para remover banimentos");
        return;
    }
    const QString uid = obj["uid"].toString();
    int removed = 0;
    for (int i = m_bans.size() - 1; i >= 0; --i)
        if (m_bans[i].uid == uid) { m_bans.removeAt(i); ++removed; }
    if (removed > 0) {
        saveBans();
        QJsonObject m = HProto::msg("ban_removed");
        m["uid"] = uid;
        c->send(m);
        log(QStringLiteral("%1 removeu banimento de %2").arg(c->name(), uid.left(16)));
    } else {
        sendError(c, "not_found", "Banimento não encontrado");
    }
}

void ServerCore::handlePrivkey(ClientSession* c, const QJsonObject& obj) {
    const QString key = obj["key"].toString();
    if (!m_privKeyGroup.contains(key)) {
        sendError(c, "bad_privkey", "Chave de privilégio inválida");
        return;
    }
    if (!m_privKeyReuse && m_usedKeys.contains(key)) {
        sendError(c, "privkey_used",
                  "Esta chave de privilégio já foi utilizada");
        return;
    }
    QString groupName = m_privKeyGroup.value(key, "admin");
    int gid = groupIdByName(groupName);
    if (gid == 0) gid = 3; // admin
    m_usedKeys.insert(key);
    saveData();
    applyGroup(c, gid, true);
    // a chave vale permanentemente para este UID
    m_assignByUid[c->uniqueId()] = gid;
    saveData();
    log(QStringLiteral("Cliente #%1 (%2) usou chave de privilégio -> grupo \"%3\"")
            .arg(c->id()).arg(c->name(), c->group()));
}

// ------------------------------------------------- grupos via protocolo (v2)
void ServerCore::handleGroupList(ClientSession* c) {
    QJsonObject m = HProto::msg("group_list");
    QJsonArray arr;
    for (const GroupDef& g : m_groups) {
        QJsonObject group = groupToJson(g);
        QJsonArray members;
        for (auto it = m_registry.cbegin(); it != m_registry.cend(); ++it) {
            const QString uid = it.key();
            const int assigned = m_assignByUid.value(uid, 2);
            if (assigned != g.id) continue;
            QJsonObject member;
            member["uid"] = uid;
            member["name"] = it.value().name;
            member["online"] = false;
            members << member;
        }
        for (ClientSession* online : m_clients) {
            if (online->groupId() != g.id) continue;
            bool already = false;
            for (const QJsonValue& v : members)
                if (v.toObject().value("uid").toString() == online->uniqueId()) already = true;
            if (already) continue;
            QJsonObject member;
            member["id"] = online->id();
            member["uid"] = online->uniqueId();
            member["name"] = online->name();
            member["online"] = true;
            members << member;
        }
        group["members"] = members;
        arr << group;
    }
    m["groups"] = arr;
    c->send(m);
}

void ServerCore::handleGroupSet(ClientSession* c, const QJsonObject& obj) {
    if (!hasPerm(c, "groupEdit")) {
        sendError(c, "no_permission", "Sem permissão para gerenciar grupos");
        return;
    }
    const QString name = obj["name"].toString().trimmed().left(30);
    const QJsonObject perms = obj["perms"].toObject();

    GroupDef g;
    const int id = obj["id"].toInt(0);
    if (id > 0) {
        // edição: name é opcional (permite mudar só permissões)
        if (!m_groups.contains(id)) { sendError(c, "not_found", "Grupo não encontrado"); return; }
        g = m_groups[id];
        // proteção anti-lockout: não deixar remover "*" de grupo que tinha "*"
        if (obj.contains("perms") && g.perms.value("*").toBool() && !perms.value("*").toBool()) {
            sendError(c, "locked", "Não é possível remover a permissão total (*) deste grupo");
            return;
        }
        if (obj.contains("name") && !name.isEmpty()) g.name = name;
        if (obj.contains("perms")) g.perms = perms;
        if (obj.contains("sigla")) g.sigla = obj["sigla"].toString();
        if (obj.contains("order")) g.order = obj["order"].toInt(0);
        if (obj.contains("icon")) g.icon = obj["icon"].toString();
        m_groups[id] = g;
    } else {
        if (name.isEmpty()) return; // criação exige nome
        g.id = m_nextGroupId++;
        g.name = name;
        g.perms = perms;
        g.sigla = obj["sigla"].toString();
        g.order = obj["order"].toInt(0);
        g.icon = obj["icon"].toString();
        if (g.perms.value("*").toBool() && !hasPerm(c, "*")) {
            sendError(c, "no_permission", "Apenas administradores (*) criam grupos com *");
            return;
        }
        m_groups[g.id] = g;
    }
    saveData();
    // clientes com este grupo mudam de rótulo se as propriedades mudaram
    for (ClientSession* o : m_clients)
        if (o->groupId() == g.id) {
            o->setGroup(g.name);
            o->setSigla(g.sigla);
            o->setIcon(g.icon);
            o->setGroupOrder(g.order);
            QJsonObject m = HProto::msg("user_group");
            m["id"] = o->id(); 
            m["group"] = o->group(); 
            m["gid"] = g.id;
            m["sigla"] = g.sigla;
            m["icon"] = g.icon;
            m["order"] = g.order;
            broadcast(m);
        }
    broadcastGroups();
    log(QStringLiteral("Grupo \"%1\" (#%2) %3 por %4")
            .arg(g.name).arg(g.id).arg(id > 0 ? "atualizado" : "criado", c->name()));
}

void ServerCore::handleGroupDelete(ClientSession* c, const QJsonObject& obj) {
    if (!hasPerm(c, "groupEdit")) {
        sendError(c, "no_permission", "Sem permissão para gerenciar grupos");
        return;
    }
    const int id = obj["id"].toInt();
    if (id < 100 || !m_groups.contains(id)) {
        sendError(c, "locked", "Grupos internos não podem ser excluídos");
        return;
    }
    m_groups.remove(id);
    for (auto it = m_assignByUid.begin(); it != m_assignByUid.end(); ++it)
        if (it.value() == id) it.value() = 1;
    for (ClientSession* o : m_clients)
        if (o->groupId() == id) applyGroup(o, 1, true);
    saveData();
    broadcastGroups();
}

void ServerCore::handleClientSetGroup(ClientSession* c, const QJsonObject& obj) {
    if (!hasPerm(c, "groupEdit")) {
        sendError(c, "no_permission", "Sem permissão para atribuir grupos");
        return;
    }
    const int gid = obj["gid"].toInt();
    if (!m_groups.contains(gid)) { sendError(c, "not_found", "Grupo não encontrado"); return; }
    // só super-admin (*) eleva outros ao grupo *
    if (m_groups[gid].perms.value("*").toBool() && !hasPerm(c, "*")) {
        sendError(c, "no_permission", "Apenas administradores (*) atribuem este grupo");
        return;
    }

    // alvo por id online ou por uid offline
    QString targetUid = obj["uid"].toString();
    if (obj.contains("id")) {
        const int cid = obj["id"].toInt();
        if (!m_clients.contains(cid)) return;
        ClientSession* t = m_clients[cid];
        targetUid = t->uniqueId();
        applyGroup(t, gid, true);
    } else if (m_registry.contains(targetUid)) {
        // offline: só persiste
    } else if (targetUid.isEmpty()) {
        return;
    }
    if (!targetUid.isEmpty()) {
        m_assignByUid[targetUid] = gid;
        saveData();
        log(QStringLiteral("%1 atribuiu grupo \"%2\" ao UID %3")
                .arg(c->name(), m_groups[gid].name, targetUid.left(16)));
        broadcastGroups();
    }
}

void ServerCore::handleServerEdit(ClientSession* c, const QJsonObject& obj) {
    if (!hasPerm(c, "serverEdit")) {
        sendError(c, "no_permission", "Sem permissão para editar o servidor");
        return;
    }
    if (obj.contains("name")) {
        const QString n = obj["name"].toString().trimmed().left(40);
        if (!n.isEmpty() && n != m_name) {
            m_name = n;
            log(QStringLiteral("Nome do servidor alterado para \"%1\" por %2").arg(n, c->name()));
        }
    }
    if (obj.contains("motd")) m_motd = obj["motd"].toString().left(200);

    bool bannerChanged = false;
    if (obj.contains("banner")) {
        const QString encoded = obj["banner"].toString();
        const QByteArray decoded = QByteArray::fromBase64(encoded.toLatin1());
        if (!encoded.isEmpty() && decoded.isEmpty()) {
            sendError(c, "invalid_banner", "Imagem de banner inválida");
            return;
        }
        if (decoded.size() > 512 * 1024) {
            sendError(c, "banner_too_big", "O banner excede o limite de 512 KiB");
            return;
        }
        const bool isPng = decoded.startsWith(QByteArray("\x89PNG\x0D\x0A\x1A\x0A", 8));
        const bool isJpeg = decoded.startsWith(QByteArray("\xFF\xD8\xFF", 3));
        const bool isGif = decoded.startsWith("GIF8");
        const bool isWebp = decoded.size() >= 12 && decoded.left(4) == "RIFF"
                         && decoded.mid(8, 4) == "WEBP";
        if (!decoded.isEmpty() && !(isPng || isJpeg || isGif || isWebp)) {
            sendError(c, "invalid_banner", "Use uma imagem PNG, JPEG, GIF ou WebP");
            return;
        }
        m_serverBanner = decoded;
        if (!saveServerBanner()) {
            sendError(c, "io_error", "Não foi possível salvar o banner do servidor");
            return;
        }
        bannerChanged = true;
    }

    saveData();
    QJsonObject m = HProto::msg("server_edit");
    m["name"] = m_name;
    m["motd"] = m_motd;
    if (bannerChanged)
        m["banner"] = QString::fromLatin1(m_serverBanner.toBase64());
    broadcast(m);
}

void ServerCore::doKick(ClientSession* c, const QString& reason, bool fromServer,
                        bool ban, int minutes) {
    QJsonObject k = HProto::msg("kicked");
    k["reason"] = reason;
    k["ban"] = ban;
    if (ban && minutes > 0) k["minutes"] = minutes;
    c->send(k);

    log(QStringLiteral("Cliente #%1 (%2) %3%4")
            .arg(c->id()).arg(c->name())
            .arg(ban ? "foi banido" : (fromServer ? "foi expulso do servidor" : "foi expulso do canal"))
            .arg(reason.isEmpty() ? QString() : QStringLiteral(" (%1)").arg(reason)));

    removeFromChannels(c->id());
    if (!fromServer && !ban) {
        // kick de canal: usuário continua conectado, volta ao padrão
        m_channels[1].users << c->id();
        QJsonObject m = HProto::msg("user_moved");
        m["id"] = c->id(); m["channel"] = 1; m["by"] = 0;
        m["reason"] = reason;
        broadcast(m);
    } else {
        QJsonObject left = HProto::msg("user_left");
        left["id"] = c->id();
        left["reason"] = ban ? "banned" : "kicked";
        broadcast(left, c->id());
        m_clients.remove(c->id());
        if (c->voiceToken()) m_byVoiceToken.remove(c->voiceToken());
        c->closeAndDelete();
    }
}

// ==================================================================== util
void ServerCore::broadcast(const QJsonObject& obj, int exceptId) {
    for (ClientSession* c : m_clients)
        if (c->id() != exceptId) c->send(obj);
}

int ServerCore::channelOfUser(int userId) const {
    for (const SvrChan& c : m_channels)
        if (c.users.contains(userId)) return c.id;
    return 0;
}

void ServerCore::removeFromChannels(int userId) {
    for (SvrChan& c : m_channels) c.users.removeAll(userId);
}

void ServerCore::addToChannel(int userId, int channelId) {
    removeFromChannels(userId);
    if (m_channels.contains(channelId))
        m_channels[channelId].users << userId;
}

ServerCore::SvrChan ServerCore::chanFromJson(const QJsonObject& o) const {
    SvrChan c;
    c.id = o["id"].toInt(1);
    c.parent = o["parent"].toInt(0);
    c.name = o["name"].toString();
    c.topic = o["topic"].toString();
    c.desc = o["desc"].toString();
    c.password = o["password"].toString();
    c.def = o["def"].toBool(false);
    c.moderated = o["moderated"].toBool(false);
    c.ntalk = o["ntalk"].toInt(0);
    c.type = o["type"].toInt(2);
    c.codec = o["codec"].toInt(4);
    c.quality = o["quality"].toInt(6);
    c.maxClients = o["max"].toInt(-1);
    c.bitrate = qBound(16, o["bitrate"].toInt(96), 384);
    c.noSymbol = o["noSymbol"].toBool(false);
    c.order = o["order"].toInt(0);
    for (const QJsonValue& v : o["linked"].toArray()) {
        const int linkedId = v.toInt();
        if (linkedId > 0 && linkedId != c.id && !c.linkedChannels.contains(linkedId))
            c.linkedChannels << linkedId;
    }
    for (const QJsonValue& v : o["ops"].toArray()) c.ops << v.toString();
    return c;
}

QJsonObject ServerCore::chanToJson(const SvrChan& c) const {
    QJsonObject j = HProto::chanJson(c.id, c.parent, c.name, c.topic, c.desc,
                                     !c.password.isEmpty(), c.id == 1, c.type, c.moderated,
                                     c.codec, c.quality, c.maxClients, c.users);
    j["ntalk"] = c.ntalk;
    j["bitrate"] = c.bitrate;
    j["noSymbol"] = c.noSymbol;
    j["order"] = c.order;
    QJsonArray linked;
    for (int linkedId : c.linkedChannels) linked << linkedId;
    j["linked"] = linked;
    QJsonArray ops;
    for (const QString& u : c.ops) ops << u;
    j["ops"] = ops;
    return j;
}

// ================================================== helpers v3
QString ServerCore::dataDir() const {
    if (m_dataFile.isEmpty()) return QDir::currentPath();
    return QFileInfo(m_dataFile).absolutePath();
}

QString ServerCore::serverBannerPath() const {
    return dataDir() + QStringLiteral("/server-banner.bin");
}

void ServerCore::loadServerBanner() {
    m_serverBanner.clear();
    QFile f(serverBannerPath());
    if (!f.exists()) return;
    if (!f.open(QIODevice::ReadOnly)) {
        log(QStringLiteral("Não foi possível abrir o banner do servidor"));
        return;
    }
    const QByteArray bytes = f.read(512 * 1024 + 1);
    if (bytes.size() > 512 * 1024) {
        log(QStringLiteral("Banner do servidor ignorado: arquivo maior que 512 KiB"));
        return;
    }
    m_serverBanner = bytes;
}

bool ServerCore::saveServerBanner() {
    if (m_serverBanner.isEmpty()) {
        return !QFile::remove(serverBannerPath()) || !QFile::exists(serverBannerPath());
    }
    QDir().mkpath(dataDir());
    QFile f(serverBannerPath());
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
    return f.write(m_serverBanner) == m_serverBanner.size();
}

QString ServerCore::avatarPath(const QString& uid) const {
    // uid é base64: trocar caracteres problemáticos de nome de arquivo
    QString safe = uid;
    safe.replace('/', '_').replace('+', '-');
    return dataDir() + QStringLiteral("/avatars/%1.avt").arg(safe);
}

QString ServerCore::iconPath(const QString& name) const {
    QString safe = sanitizeFileName(name);
    return dataDir() + QStringLiteral("/icons/%1").arg(safe);
}

QString ServerCore::filesDir(int chan) const {
    return dataDir() + QStringLiteral("/files/%1").arg(chan);
}

QString ServerCore::sanitizeFileName(const QString& n) {
    QString out;
    for (const QChar& ch : n.left(60))
        if (ch.isLetterOrNumber() || ch == QLatin1Char('.') || ch == QLatin1Char('_')
                || ch == QLatin1Char('-') || ch == QLatin1Char(' '))
            out += ch;
    if (out.isEmpty() || out.startsWith(QLatin1Char('.'))) out.prepend(QLatin1Char('_'));
    return out;
}

bool ServerCore::isChanOp(const ClientSession* c, int channelId) const {
    if (!c || !m_channels.contains(channelId)) return false;
    return m_channels[channelId].ops.contains(c->uniqueId());
}

void ServerCore::removeChannelFiles(int chan) {
    for (int i = m_files.size() - 1; i >= 0; --i)
        if (m_files[i].chan == chan) m_files.removeAt(i);
    QDir(filesDir(chan)).removeRecursively();
}

void ServerCore::loadAvatars() {
    m_avatarHash.clear();
    QDir d(dataDir() + QStringLiteral("/avatars"));
    for (const QFileInfo& fi : d.entryInfoList({QStringLiteral("*.avt")}, QDir::Files)) {
        QString uid = fi.completeBaseName();
        uid.replace('_', '/').replace('-', '+');
        // hash = sha1 do conteúdo
        QFile f(fi.absoluteFilePath());
        if (f.open(QIODevice::ReadOnly))
            m_avatarHash[uid] = QString::fromLatin1(
                QCryptographicHash::hash(f.readAll(), QCryptographicHash::Sha1).toHex());
    }
}

void ServerCore::relayVoice(ClientSession* sender, quint16 seq, const QByteArray& payload) {
    if (!sender || !m_voice || payload.isEmpty()) return;
    const int chan = channelOfUser(sender->id());
    if (chan == 0 || !m_channels.contains(chan)) return;

    // A permissão de fala continua sendo avaliada no canal em que o remetente
    // está. O vínculo somente amplia os canais que escutam esse áudio.
    if (!canTalkIn(sender, chan)) return;

    // Monta o componente conectado do canal de origem. Isso permite que uma
    // seleção A+B+C continue funcionando mesmo que os vínculos tenham sido
    // criados em operações diferentes (A-B e depois B-C).
    QSet<int> linked;
    QList<int> pending;
    linked.insert(chan);
    pending << chan;
    while (!pending.isEmpty()) {
        const int current = pending.takeFirst();
        if (!m_channels.contains(current)) continue;
        for (int next : m_channels[current].linkedChannels) {
            if (m_channels.contains(next) && !linked.contains(next)) {
                linked.insert(next);
                pending << next;
            }
        }
        // Aceita também bancos antigos eventualmente assimétricos e corrige a
        // entrega sem exigir que o administrador refaça os vínculos.
        for (const SvrChan& candidate : m_channels) {
            if (candidate.linkedChannels.contains(current) && !linked.contains(candidate.id)) {
                linked.insert(candidate.id);
                pending << candidate.id;
            }
        }
    }

    const QSet<int> whisper = sender->whisperIds();   // v3: sussurro para alvos específicos
    const QByteArray packet = HProto::encodeVoiceServer(quint32(sender->id()), seq, payload);
    for (ClientSession* c : m_clients) {
        if (c == sender) continue;
        if (c->udpPort() == 0) continue;
        const int targetChan = channelOfUser(c->id());
        if (targetChan == 0) continue;
        if (!whisper.isEmpty()) {
            if (!whisper.contains(c->id())) continue;        // sussurro: só os alvos
        } else if (!linked.contains(targetChan)) continue;   // canal ou vínculo
        if (!hasChannelPerm(c, targetChan, QStringLiteral("listen"))) continue;
        m_voice->sendTo(c->udpAddress(), c->udpPort(), packet);
    }
}
