#pragma once

#include <QObject>
#include <QTcpServer>
#include <QMap>
#include <QSet>
#include <QJsonObject>
#include <QByteArray>
#include <QTimer>
#include <QHostAddress>
#include <QDateTime>
#include <QSet>
#include <functional>

class ClientSession;
class VoiceRelay;

// v3: reclamação registrada contra um cliente
struct Complaint {
    QString uid, name, byUid, byName, text;
    QDateTime ts;
};
// v3: mensagem offline pendente
struct OfflineMsg {
    QString fromUid, fromName, text;
    QDateTime ts;
};
// v3: metadados de um arquivo de canal
struct FileMeta {
    int chan; QString name, byUid, by; qint64 size;
    QDateTime ts;
};

struct BanEntry {
    QString uid;
    QString ip;
    QString name;
    QString reason;
    QDateTime expires; // inválido = permanente
};

// Grupo de servidor com permissões granulares (Cenário 3)
struct GroupDef {
    int id = 0;
    QString name;
    QString sigla; // tag/abbreviation, e.g. "[Mod]"
    int order = 0; // sorting index/hierarchy order (for display)
    int position = 0; // Pilar 1: posição hierárquica (quanto maior, mais autoridade) - Discord-style
    QString icon;  // icon identifier or index
    QJsonObject perms; // { "*":true } = tudo; chaves: kick, ban, banList, move,
                       // chanCreateTemp, chanCreateSemi, chanCreatePerm, chanEdit,
                       // chanDelete, serverEdit, groupEdit, poke, privmsg,
                       // ignoreChanPass, ignoreTalkPower, talkPower (int)
};

// Registro persistente de identidade (UID) já vista no servidor
struct RegClient {
    QString name;
    QDateTime firstSeen;
    QDateTime lastSeen;
};

// Núcleo do servidor Halla: sessões, canais, permissões, chat, moderação.
class ServerCore : public QObject {
    Q_OBJECT
public:
    explicit ServerCore(QObject* parent = nullptr);
    ~ServerCore() override;

    bool start(quint16 controlPort, quint16 voicePort);

    // config
    void setServerName(const QString& n)    { m_name = n; }
    void setMotd(const QString& m)          { m_motd = m; }
    void setMaxClients(int n)               { m_maxClients = (n <= 0) ? 32 : n; }
    void setPassword(const QString& p)      { m_password = p; }
    void setAdminPassword(const QString& p) { m_adminPassword = p; }
    void setPrivilegeKeys(const QStringList& keys);
    void setPrivilegeKeyReuse(bool on)      { m_privKeyReuse = on; }
    void setDataFile(const QString& f)      { m_dataFile = f; }
    void setBanFile(const QString& f)       { m_banFile = f; }
    void setDatabaseFile(const QString& f)  { m_dbFile = f; }
    void setDatabaseType(const QString& t)  { m_dbType = t; }
    void setDatabaseHost(const QString& h)  { m_dbHost = h; }
    void setDatabasePort(int p)             { m_dbPort = p; }
    void setDatabaseName(const QString& n)  { m_dbName = n; }
    void setDatabaseUser(const QString& u)  { m_dbUser = u; }
    void setDatabasePassword(const QString& p) { m_dbPassword = p; }
    void setVersion(const QString& v)       { m_version = v; }
    void setAllowScreenShare(bool on)       { m_allowScreenShare = on; }
    bool allowScreenShare() const           { return m_allowScreenShare; }
    void setScreenshareWidth(int w)         { m_screenshareWidth = w; }
    int screenshareWidth() const            { return m_screenshareWidth; }
    void setScreenshareHeight(int h)        { m_screenshareHeight = h; }
    int screenshareHeight() const           { return m_screenshareHeight; }
    void setScreenshareFps(int f)           { m_screenshareFps = f; }
    int screenshareFps() const              { return m_screenshareFps; }
    void setCertificateFile(const QString& f) { m_certFile = f; }
    void setPrivateKeyFile(const QString& f)  { m_keyFile = f; }

    void log(const QString& msg);
    int clientCount() const { return m_clients.size(); }

    // ---- ServerQuery (interface administrativa em texto, porta 10011)
    friend class ServerQuery;
    QString version() const         { return m_version; }
    QString platform() const {
#ifdef Q_OS_WIN
        return QStringLiteral("Windows");
#else
        return QStringLiteral("Linux");
#endif
    }
    QString serverName() const      { return m_name; }
    QString motd() const            { return m_motd; }
    int maxClients() const          { return m_maxClients; }
    quint16 port() const            { return m_controlPort; }
    QString queryPassword() const   { return m_queryPass; }
    void setQueryPassword(const QString& p);
    void queryCounts(int& channels, int& clients) const;
    void queryCommand(class QTcpSocket* s, const QString& cmd,
                      const QMap<QString, QString>& args,
                      const std::function<void(class QTcpSocket*)>& ok,
                      const std::function<void(class QTcpSocket*, int,
                                               const QString&)>& err);

    ClientSession* clientByVoiceToken(quint32 token) { return m_byVoiceToken.value(token, nullptr); }
    void relayVoice(ClientSession* sender, quint16 seq, const QByteArray& payload);
    void relayScreenShare(ClientSession* sender, quint16 seq, const QByteArray& payload);
    QJsonObject voiceStats() const;

signals:
    void logLine(const QString& text);

public slots:
    void onNewConnection();
    void onClientMessage(ClientSession* client, const QJsonObject& obj);
    void onClientDisconnected(ClientSession* client);
    void checkIdleClients();

private:
    QTcpServer* m_tcp = nullptr;
    VoiceRelay* m_voice = nullptr;

    QString m_name = "Servidor Halla";
    QString m_motd = "Bem-vindo ao Halla!";
    QString m_version = "3.0.0";
    quint16 m_controlPort = 9987;
    QString m_queryPass;              // senha do ServerQuery (persistida)
    int m_maxClients = 32;
    QString m_password;
    QString m_adminPassword;
    QMap<QString, QString> m_privKeyGroup; // chave -> nome do grupo concedido
    bool m_privKeyReuse = false;
    bool m_allowScreenShare = false;
    int m_screenshareWidth = 1280;
    int m_screenshareHeight = 720;
    int m_screenshareFps = 12;
    QString m_dataFile;
    QString m_banFile;
    QString m_dbFile;
    QString m_dbType = "sqlite";
    QString m_dbHost = "localhost";
    int m_dbPort = 3306;
    QString m_dbName = "halla_db";
    QString m_dbUser = "root";
    QString m_dbPassword;
    QString m_certFile;
    QString m_keyFile;

    QMap<int, ClientSession*> m_clients;
    QMap<quint32, ClientSession*> m_byVoiceToken;
    int m_nextId = 1;
    quint32 m_nextToken = 1;

    // canais em memória (persistidos em JSON)
    struct SvrChan {
        int id; int parent; QString name, topic, desc, password;
        bool def, moderated, noSymbol; int ntalk; // talk power necessário (0 = usa moderated?25:0)
        int type, codec, quality, maxClients;
        int bitrate = 96; // de 16kbps a 384kbps (padrão 96)
        int order = 0;    // posição relativa entre canais irmãos
        // Pilar 3: Permissões exclusivas de canal (Discord-style Overrides)
        // GrupoOverride: { "groupId": { "permKey": state } } onde state é:
        //   1 = Allow (permite/força), 0 = Deny (nega/corta), -1 = Inherit (herda do servidor)
        QJsonObject groupPerms; // permissões de canais por cargo/grupo { "groupId": { "perm": state } }
        // Pilar 1: Hierarquia - mapeia grupo -> posição mínima necessária para operar no canal
        QJsonObject groupPositionReqs; // { "groupId": minPosition } - exige position >= valor
        QList<int> linkedChannels; // relação simétrica de áudio entre canais
        QList<int> users;
        QList<QString> ops; // v3: UIDs dos operadores do canal (criador + promovidos)
    };
    QMap<int, SvrChan> m_channels;
    int m_nextChanId = 1;
    QMap<int, QByteArray> m_channelKeys; // channelId -> key (16 bytes)
    void rotateChannelKey(int channelId);

    // Cenário 3: grupos, atribuições, chaves usadas, registro de UIDs
    QMap<int, GroupDef> m_groups;            // id -> definição (builtin 1..3, custom >=100)
    int m_nextGroupId = 100;
    QMap<QString, QList<int>> m_assignByUid;        // uid -> list of groupIds (persistente)
    QSet<QString> m_privilegedUids;         // UID com privilégio individual total
    QSet<QString> m_usedKeys;                // chaves de privilégio já consumidas
    QMap<QString, RegClient> m_registry;     // uid -> dados (primeira/última vez)

    QList<BanEntry> m_bans;
    QTimer* m_idleTimer = nullptr;

    // ---- v3: avatares, offline, reclamações, arquivos
    QMap<QString, QString> m_avatarHash;            // uid -> hash ("" = sem avatar)
    QByteArray m_serverBanner;                      // imagem do banner global (PNG/JPEG/WebP)
    QList<Complaint> m_complaints;
    QMap<QString, QList<OfflineMsg>> m_offline;     // uid destino -> mensagens
    QList<FileMeta> m_files;

    QString dataDir() const;                        // diretório do dataFile
    QString serverBannerPath() const;
    void loadServerBanner();
    bool saveServerBanner();
    QString avatarPath(const QString& uid) const;
    QString iconPath(const QString& name) const;
    QString filesDir(int chan) const;
    void loadAvatars();
    bool initDatabase();
    void loadDataFromJson();
    void loadBansFromJson();
    void saveDataToSql();
    void saveBansToSql();
    bool isChanOp(const ClientSession* c, int channelId) const;
    static QString sanitizeFileName(const QString& n);
    void removeChannelFiles(int chan);

    void loadData();
    void saveData();
    void loadBans();
    void saveBans();

    void handleHello(ClientSession* c, const QJsonObject& obj);
    void handleChat(ClientSession* c, const QJsonObject& obj);
    void handleMove(ClientSession* c, const QJsonObject& obj);
    void handleMoveOther(ClientSession* c, const QJsonObject& obj);
    void handleCommander(ClientSession* c, const QJsonObject& obj);
    void handleStatus(ClientSession* c, const QJsonObject& obj);
    void handleNick(ClientSession* c, const QJsonObject& obj);
    void handleDesc(ClientSession* c, const QJsonObject& obj);
    void handlePoke(ClientSession* c, const QJsonObject& obj);
    void handleChanCreate(ClientSession* c, const QJsonObject& obj);
    void handleChanEdit(ClientSession* c, const QJsonObject& obj);
    void handleChanMove(ClientSession* c, const QJsonObject& obj);
    void handleChanLink(ClientSession* c, const QJsonObject& obj);
    void handleChanDelete(ClientSession* c, const QJsonObject& obj);
    void handleKick(ClientSession* c, const QJsonObject& obj);
    void handleBan(ClientSession* c, const QJsonObject& obj);
    void handleBanList(ClientSession* c);
    void handleUnban(ClientSession* c, const QJsonObject& obj);
    void handlePrivkey(ClientSession* c, const QJsonObject& obj);
    void handleVolume(ClientSession* c, const QJsonObject& obj);
    void handleGroupList(ClientSession* c);
    void handleGroupSet(ClientSession* c, const QJsonObject& obj);
    void handleGroupDelete(ClientSession* c, const QJsonObject& obj);
    void handleClientSetGroup(ClientSession* c, const QJsonObject& obj);
    void handleServerEdit(ClientSession* c, const QJsonObject& obj);
    void handleTalking(ClientSession* c, const QJsonObject& obj);
    // ---- v3
    void handleAvatarSet(ClientSession* c, const QJsonObject& obj);
    void handleAvatarGet(ClientSession* c, const QJsonObject& obj);
    void handleIconGet(ClientSession* c, const QJsonObject& obj);
    void handleIconSet(ClientSession* c, const QJsonObject& obj);
    void handleOfflineSend(ClientSession* c, const QJsonObject& obj);
    void handleComplaintAdd(ClientSession* c, const QJsonObject& obj);
    void handleComplaintList(ClientSession* c);
    void handleComplaintClear(ClientSession* c, const QJsonObject& obj);
    void handleWhisper(ClientSession* c, const QJsonObject& obj);
    void handleFtUpload(ClientSession* c, const QJsonObject& obj);
    void handleFtList(ClientSession* c, const QJsonObject& obj);
    void handleFtDownload(ClientSession* c, const QJsonObject& obj);
    void handleFtDelete(ClientSession* c, const QJsonObject& obj);

    // permissões
    bool hasPerm(const ClientSession* c, const char* key) const;
    bool hasChannelPerm(const ClientSession* c, int channelId, const QString& permKey) const;
    int talkPower(const ClientSession* c) const;
    static QJsonObject myPermsOf(const GroupDef& g);
    void applyGroup(ClientSession* c, int groupId, bool announce);
    int groupIdByName(const QString& name) const;
    void setupBuiltinGroups();
    
    // Pilar 1: Hierarquia de Cargos (Discord-style position)
    int clientPosition(const ClientSession* c) const;
    bool canManageClient(const ClientSession* executor, const ClientSession* target) const;
    bool canManageGroup(int executorGroupId, int targetGroupId) const;
    
    // Pilar 3: Resolver permissão de canal com overrides (Allow/Deny/Inherit)
    int getChannelPermState(const ClientSession* c, int channelId, const QString& permKey) const;
    bool hasEffectiveChannelPerm(const ClientSession* c, int channelId, const QString& permKey) const;

    void sendError(ClientSession* c, const QString& code, const QString& msg);
    void broadcast(const QJsonObject& obj, int exceptId = -1);
    void broadcastGroups();
    void sendWelcome(ClientSession* c);
    void doKick(ClientSession* c, const QString& reason, bool fromServer, bool ban, int minutes = 0);
    void registerClient(ClientSession* c);
    int channelOfUser(int userId) const;
    void removeFromChannels(int userId);
    void addToChannel(int userId, int channelId);
    SvrChan chanFromJson(const QJsonObject& o) const;
    QJsonObject chanToJson(const SvrChan& c) const;
    QJsonObject groupToJson(const GroupDef& g) const;
    bool canTalkIn(const ClientSession* c, int channelId) const;
};
