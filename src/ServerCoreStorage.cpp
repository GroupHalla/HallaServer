#include "ServerCore.h"
#include "ClientSession.h"
#include "HallaProtocol.h"

#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonArray>
#include <QDir>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QRandomGenerator>

// Persistência e banco de dados do ServerCore. Mantido separado do fluxo de
// sessão/rede para reduzir o tamanho do antigo ServerCore.cpp monolítico.

static bool ensureGroupRuntimeDefaults(GroupDef& g) {
    bool changed = false;
    // Versões antigas não tinham a permissão global "listen", mas relayVoice
    // passou a checá-la. Sem esta migração, clientes normais/mobile entram e
    // veem o indicador de fala via TCP, porém o servidor não retransmite UDP.
    if (!g.perms.contains(QStringLiteral("listen"))) {
        g.perms[QStringLiteral("listen")] = true;
        changed = true;
    }
    if (!g.perms.contains(QStringLiteral("text_chat"))) {
        g.perms[QStringLiteral("text_chat")] = true;
        changed = true;
    }
    return changed;
}

void ServerCore::loadData() {
    m_channels.clear();
    m_groups.clear();
    setupBuiltinGroups();

    SvrChan def{1, 0, QStringLiteral("Canal padrão"), QString(), QString(), QString(),
                true, false, false, 0, 2, 4, 6, -1, 96};
    m_channels.insert(1, def);
    m_nextChanId = 2;

    if (!initDatabase()) {
        log(QStringLiteral("Erro grave: Não foi possível inicializar o banco de dados %1!").arg(m_dbType.toUpper()));
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

        // Tenta carregar canais - verifica se as colunas existem
        if (!q.exec("SELECT `id`, `parentId`, `name`, `topic`, `desc`, `password`, `isDefault`, `type`, `moderated`, `codec`, `codecQuality`, `maxClients`, `ntalk`, `bitrate`, `group_perms`, `no_symbol`, `order_index`, `linked_channels`, `group_position_reqs`, `temp_channel_parent` FROM channels")) {
            log("AVISO: Falha ao carregar canais - talvez as colunas não existam. Erro: " + q.lastError().text());
            // Tenta versão sem a coluna nova
            if (q.exec("SELECT `id`, `parentId`, `name`, `topic`, `desc`, `password`, `isDefault`, `type`, `moderated`, `codec`, `codecQuality`, `maxClients`, `ntalk`, `bitrate`, `group_perms`, `no_symbol`, `order_index`, `linked_channels` FROM channels")) {
                log("Carregando canais com esquema antigo (sem group_position_reqs)");
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
                    // groupPositionReqs vazio para esquema antigo
                    if (c.id == 1) m_channels[1] = c; else m_channels.insert(c.id, c);
                    m_nextChanId = qMax(m_nextChanId, c.id + 1);
                }
            }
        } else {
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
                // Pilar 1: Requisitos de position por grupo no canal
                c.groupPositionReqs = QJsonDocument::fromJson(q.value(18).toString().toUtf8()).object();
                c.tempChannelParent = q.value(19).toInt() != 0;
                
                if (c.id == 1) {
                    m_channels[1] = c;
                } else {
                    m_channels.insert(c.id, c);
                }
                m_nextChanId = qMax(m_nextChanId, c.id + 1);
            }
        }

        // Mantém no máximo um destino global e nunca aceita um canal
        // temporário como pai de outros canais temporários.
        int configuredTempParent = 0;
        for (SvrChan& channel : m_channels) {
            if (!channel.tempChannelParent) continue;
            if (channel.type == 0 || configuredTempParent != 0)
                channel.tempChannelParent = false;
            else
                configuredTempParent = channel.id;
        }

        if (q.exec("SELECT id, name, sigla, order_index, icon, perms, position, sigla_after, order_enabled FROM groups")) {
            while (q.next()) {
                GroupDef g;
                g.id = q.value(0).toInt();
                g.name = q.value(1).toString();
                g.sigla = q.value(2).toString();
                g.order = q.value(3).toInt();
                g.icon = q.value(4).toString();
                g.position = q.value(6).toInt(0);  // Pilar 1: position hierárquico
                g.siglaAfter = q.value(7).toBool();
                g.orderEnabled = q.value(8).toBool();
                
                QJsonDocument doc = QJsonDocument::fromJson(q.value(5).toString().toUtf8());
                g.perms = doc.object();
                
                if (g.id >= 100) {
                    m_groups[g.id] = g;
                    m_nextGroupId = qMax(m_nextGroupId, g.id + 1);
                } else {
                    // Atualiza campos de sigla, order, icon e position nos grupos built-in carregados
                    if (m_groups.contains(g.id)) {
                        m_groups[g.id].sigla = g.sigla;
                        m_groups[g.id].siglaAfter = g.siglaAfter;
                        m_groups[g.id].order = g.order;
                        m_groups[g.id].orderEnabled = g.orderEnabled;
                        m_groups[g.id].icon = g.icon;
                        m_groups[g.id].position = g.position;  // Pilar 1
                    }
                }
            }
        }
        for (GroupDef& g : m_groups) ensureGroupRuntimeDefaults(g);

        if (q.exec("SELECT uid, groupId FROM assignments")) {
            while (q.next()) {
                m_assignByUid[q.value(0).toString()] << q.value(1).toInt();
            }
        }

        if (q.exec("SELECT uid FROM privileges")) {
            while (q.next()) m_privilegedUids.insert(q.value(0).toString());
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
            // Gera uma nova chave segura no formato Halla
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
    
    log(QStringLiteral("Dados carregados do %1: %2 canais, %3 grupos, %4 identidades")
            .arg(m_dbType.toUpper())
            .arg(m_channels.size()).arg(m_groups.size()).arg(m_registry.size()));
}


bool ServerCore::ensureSqlConnection() {
    if (!QSqlDatabase::contains(QStringLiteral("HallaServerConnection"))) {
        return initDatabase();
    }
    QSqlDatabase db = QSqlDatabase::database(QStringLiteral("HallaServerConnection"));
    if (db.isOpen()) {
        QSqlQuery ping(db);
        if (m_dbType != QStringLiteral("mysql") || ping.exec(QStringLiteral("SELECT 1"))) {
            return true;
        }
        log(QStringLiteral("SQL: conexão aparentemente caiu; tentando reconectar: %1").arg(ping.lastError().text()));
    }
    db.close();
    if (!db.open()) {
        log(QStringLiteral("SQL RECONNECT FAILED: %1").arg(db.lastError().text()));
        return false;
    }
    log(QStringLiteral("SQL: conexão com banco restabelecida"));
    return true;
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
           "`linked_channels` TEXT, "
           "`group_position_reqs` TEXT, "
           "`temp_channel_parent` INT NOT NULL DEFAULT 0"
           ")");  // Pilar 1: requisitos de position por grupo no canal
    // Migração silenciosa de bancos criados antes das opções visuais e de
    // áudio vinculado. O erro de coluna já existente é intencionalmente
    // ignorado para manter bancos atuais compatíveis.
    q.exec("ALTER TABLE channels ADD COLUMN `no_symbol` INT DEFAULT 0");
    q.exec("ALTER TABLE channels ADD COLUMN `order_index` INT DEFAULT 0");
    q.exec("ALTER TABLE channels ADD COLUMN `linked_channels` TEXT");
    q.exec("ALTER TABLE channels ADD COLUMN `group_position_reqs` TEXT");  // Pilar 1
    q.exec("ALTER TABLE channels ADD COLUMN `temp_channel_parent` INT NOT NULL DEFAULT 0");
           
    q.exec("CREATE TABLE IF NOT EXISTS groups ("
           "`id` INT PRIMARY KEY, "
           "`name` VARCHAR(255), "
           "`sigla` VARCHAR(255), "
           "`order_index` INT, "
           "`icon` VARCHAR(255), "
           "`perms` TEXT, "
           "`position` INT DEFAULT 0, "
           "`sigla_after` INT NOT NULL DEFAULT 0, "
           "`order_enabled` INT NOT NULL DEFAULT 1"
           ")");  // Pilar 1: position hierárquica do grupo
    // Compatibilidade com bancos existentes: antes = prefixo e a ordem
    // participava da lista, exatamente como nas versões anteriores.
    q.exec("ALTER TABLE groups ADD COLUMN `sigla_after` INT NOT NULL DEFAULT 0");
    q.exec("ALTER TABLE groups ADD COLUMN `order_enabled` INT NOT NULL DEFAULT 1");
           
    q.exec("CREATE TABLE IF NOT EXISTS assignments ("
           "`uid` VARCHAR(255) PRIMARY KEY, "
           "`groupId` INT"
           ")");
           
    // Migração dinâmica dialeto-agnóstica de assignments para chave primária composta (suporte a múltiplos cargos)
    bool needsMigration = true;
    if (q.exec("INSERT INTO assignments (uid, groupId) VALUES ('test_migration_uid', 9999)")) {
        if (q.exec("INSERT INTO assignments (uid, groupId) VALUES ('test_migration_uid', 9998)")) {
            needsMigration = false;
        }
        q.exec("DELETE FROM assignments WHERE uid = 'test_migration_uid'");
    }
    if (needsMigration) {
        log("Iniciando migração da tabela assignments para chave composta...");
        q.exec("CREATE TABLE IF NOT EXISTS assignments_v2 ("
               "`uid` VARCHAR(255), "
               "`groupId` INT, "
               "PRIMARY KEY (`uid`, `groupId`)"
               ")");
        q.exec("INSERT INTO assignments_v2 (uid, groupId) SELECT uid, groupId FROM assignments");
        q.exec("DROP TABLE assignments");
        q.exec("CREATE TABLE assignments ("
               "`uid` VARCHAR(255), "
               "`groupId` INT, "
               "PRIMARY KEY (`uid`, `groupId`)"
               ")");
        q.exec("INSERT INTO assignments (uid, groupId) SELECT uid, groupId FROM assignments_v2");
        q.exec("DROP TABLE assignments_v2");
        log("Migração de assignments concluída com sucesso!");
    }
           
    q.exec("CREATE TABLE IF NOT EXISTS used_keys ("
           "`key_val` VARCHAR(255) PRIMARY KEY"
           ")");
    q.exec("CREATE TABLE IF NOT EXISTS privileges ("
           "`uid` VARCHAR(255) PRIMARY KEY"
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
        g.siglaAfter = o["siglaAfter"].toBool(false);
        g.order = o["order"].toInt(0);
        g.orderEnabled = o["orderEnabled"].toBool(true);
        g.icon = o["icon"].toString();
        g.position = o["position"].toInt(0);  // Pilar 1: position hierárquica
        if (g.id >= 100 && !g.name.isEmpty()) {
            m_groups[g.id] = g;
            m_nextGroupId = qMax(m_nextGroupId, g.id + 1);
        } else if (m_groups.contains(g.id)) {
            m_groups[g.id].sigla = g.sigla;
            m_groups[g.id].siglaAfter = g.siglaAfter;
            m_groups[g.id].order = g.order;
            m_groups[g.id].orderEnabled = g.orderEnabled;
            m_groups[g.id].icon = g.icon;
            m_groups[g.id].position = g.position;  // Pilar 1
        }
    }
    for (GroupDef& g : m_groups) ensureGroupRuntimeDefaults(g);
    const QJsonObject assign = root["assignments"].toObject();
    for (auto it = assign.begin(); it != assign.end(); ++it) {
        if (it.value().isArray()) {
            for (const QJsonValue& gv : it.value().toArray()) {
                m_assignByUid[it.key()] << gv.toInt();
            }
        } else {
            m_assignByUid[it.key()] << it.value().toInt();
        }
    }
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
    // Só salva se houver dados carregados no servidor
    if (m_channels.isEmpty() && m_groups.isEmpty()) {
        log("AVISO: não será salvo pois não há dados carregados no servidor");
        return;
    }
    saveDataToSql();
}

void ServerCore::saveDataToSql() {
    if (!ensureSqlConnection()) {
        log("SQL SAVE ERROR: Database is not open and reconnect failed!");
        return;
    }
    QSqlDatabase db = QSqlDatabase::database("HallaServerConnection");

    if (!db.transaction()) {
        log("SQL SAVE ERROR: could not start transaction: " + db.lastError().text());
        if (!m_sqlSaveRetrying && m_dbType == QStringLiteral("mysql")) {
            m_sqlSaveRetrying = true;
            db.close();
            if (ensureSqlConnection()) saveDataToSql();
            m_sqlSaveRetrying = false;
        }
        return;
    }
    QSqlQuery q(db);

    bool ok = true;
    ok &= q.exec("DELETE FROM settings");
    ok &= q.exec("DELETE FROM channels");
    ok &= q.exec("DELETE FROM groups");
    ok &= q.exec("DELETE FROM assignments");
    ok &= q.exec("DELETE FROM used_keys");
    ok &= q.exec("DELETE FROM privileges");
    ok &= q.exec("DELETE FROM clients");
    ok &= q.exec("DELETE FROM complaints");
    ok &= q.exec("DELETE FROM offline_messages");
    ok &= q.exec("DELETE FROM files");
    if (!ok) {
        log("SQL SAVE ERROR on DELETE: " + q.lastError().text());
        db.rollback();
        if (!m_sqlSaveRetrying && m_dbType == QStringLiteral("mysql")) {
            m_sqlSaveRetrying = true;
            db.close();
            if (ensureSqlConnection()) saveDataToSql();
            m_sqlSaveRetrying = false;
        }
        return;
    }

    q.prepare("INSERT INTO settings (`key`, `value`) VALUES (:key, :value)");
    q.bindValue(":key", "name"); q.bindValue(":value", m_name); q.exec();
    q.bindValue(":key", "motd"); q.bindValue(":value", m_motd); q.exec();
    if (!m_queryPass.isEmpty()) {
        q.bindValue(":key", "queryPass"); q.bindValue(":value", m_queryPass); q.exec();
    }

    q.prepare("INSERT INTO channels (`id`, `parentId`, `name`, `topic`, `desc`, `password`, `isDefault`, `type`, `moderated`, `codec`, `codecQuality`, `maxClients`, `ntalk`, `bitrate`, `group_perms`, `no_symbol`, `order_index`, `linked_channels`, `group_position_reqs`, `temp_channel_parent`) "
              "VALUES (:id, :parentId, :name, :topic, :desc, :password, :isDefault, :type, :moderated, :codec, :codecQuality, :maxClients, :ntalk, :bitrate, :group_perms, :no_symbol, :order_index, :linked_channels, :group_position_reqs, :temp_channel_parent)");
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
        // Pilar 1: Salva requisitos de position por grupo no canal
        q.bindValue(":group_position_reqs",
                    QString::fromUtf8(QJsonDocument(c.groupPositionReqs).toJson(QJsonDocument::Compact)));
        q.bindValue(":temp_channel_parent", c.tempChannelParent ? 1 : 0);
        if (!q.exec()) {
            log("SQL SAVE ERROR on channels: " + q.lastError().text());
        }
    }

    q.prepare("INSERT INTO groups (`id`, `name`, `sigla`, `order_index`, `icon`, `perms`, `position`, `sigla_after`, `order_enabled`) "
              "VALUES (:id, :name, :sigla, :order_index, :icon, :perms, :position, :sigla_after, :order_enabled)");
    for (const GroupDef& g : m_groups) {
        q.bindValue(":id", g.id);
        q.bindValue(":name", g.name);
        q.bindValue(":sigla", g.sigla);
        q.bindValue(":order_index", g.order);
        q.bindValue(":icon", g.icon);
        q.bindValue(":perms", QString::fromUtf8(QJsonDocument(g.perms).toJson(QJsonDocument::Compact)));
        q.bindValue(":position", g.position);  // Pilar 1: position hierárquica
        q.bindValue(":sigla_after", g.siglaAfter ? 1 : 0);
        q.bindValue(":order_enabled", g.orderEnabled ? 1 : 0);
        if (!q.exec()) {
            log("SQL SAVE ERROR on groups: " + q.lastError().text());
        }
    }

    q.prepare("INSERT INTO assignments (`uid`, `groupId`) VALUES (:uid, :groupId)");
    for (auto it = m_assignByUid.begin(); it != m_assignByUid.end(); ++it) {
        for (int gid : it.value()) {
            q.bindValue(":uid", it.key());
            q.bindValue(":groupId", gid);
            if (!q.exec()) {
                log(QStringLiteral("SQL SAVE ERROR on assignments (uid=%1, gid=%2): %3")
                    .arg(it.key()).arg(QString::number(gid)).arg(q.lastError().text()));
            }
        }
    }

    q.prepare("INSERT INTO privileges (`uid`) VALUES (:uid)");
    for (const QString& uid : m_privilegedUids) { q.bindValue(":uid", uid); q.exec(); }

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
        db.rollback();
        if (!m_sqlSaveRetrying && m_dbType == QStringLiteral("mysql")) {
            m_sqlSaveRetrying = true;
            db.close();
            if (ensureSqlConnection()) saveDataToSql();
            m_sqlSaveRetrying = false;
        }
    } else {
        m_sqlSaveRetrying = false;
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
    if (!ensureSqlConnection()) return;
    QSqlDatabase db = QSqlDatabase::database("HallaServerConnection");

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

