#pragma once

#include <QObject>
#include <QTcpServer>
#include <QMap>
#include <QSet>
#include <QJsonObject>
#include <QTimer>
#include <QHostAddress>
#include <QDateTime>

class ClientSession;
class VoiceRelay;

struct BanEntry {
    QString uid;
    QString name;
    QString reason;
    QDateTime expires; // inválido = permanente
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
    void setMaxClients(int n)               { m_maxClients = n; }
    void setPassword(const QString& p)      { m_password = p; }
    void setAdminPassword(const QString& p) { m_adminPassword = p; }
    void setPrivilegeKeys(const QStringList& keys) { m_privilegeKeys = keys; }
    void setDataFile(const QString& f)      { m_dataFile = f; }
    void setBanFile(const QString& f)       { m_banFile = f; }

    void log(const QString& msg);
    int clientCount() const { return m_clients.size(); }

    ClientSession* clientByVoiceToken(quint32 token) { return m_byVoiceToken.value(token, nullptr); }
    void relayVoice(ClientSession* sender, quint16 seq, const QByteArray& payload);

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
    int m_maxClients = 32;
    QString m_password;
    QString m_adminPassword;
    QStringList m_privilegeKeys;
    QString m_dataFile;
    QString m_banFile;

    QMap<int, ClientSession*> m_clients;
    QMap<quint32, ClientSession*> m_byVoiceToken;
    int m_nextId = 1;
    quint32 m_nextToken = 1;

    // canais em memória (persistidos em JSON)
    struct SvrChan {
        int id; int parent; QString name, topic, desc, password;
        bool def, moderated; int type, codec, quality, maxClients;
        QList<int> users;
    };
    QMap<int, SvrChan> m_channels;
    int m_nextChanId = 1;

    QList<BanEntry> m_bans;
    QTimer* m_idleTimer = nullptr;

    void loadData();
    void saveData();
    void loadBans();
    void saveBans();

    void handleHello(ClientSession* c, const QJsonObject& obj);
    void handleChat(ClientSession* c, const QJsonObject& obj);
    void handleMove(ClientSession* c, const QJsonObject& obj);
    void handleStatus(ClientSession* c, const QJsonObject& obj);
    void handleNick(ClientSession* c, const QJsonObject& obj);
    void handleDesc(ClientSession* c, const QJsonObject& obj);
    void handlePoke(ClientSession* c, const QJsonObject& obj);
    void handleChanCreate(ClientSession* c, const QJsonObject& obj);
    void handleChanEdit(ClientSession* c, const QJsonObject& obj);
    void handleChanDelete(ClientSession* c, const QJsonObject& obj);
    void handleKick(ClientSession* c, const QJsonObject& obj);
    void handleBan(ClientSession* c, const QJsonObject& obj);
    void handlePrivkey(ClientSession* c, const QJsonObject& obj);
    void handleVolume(ClientSession* c, const QJsonObject& obj);

    void broadcast(const QJsonObject& obj, int exceptId = -1);
    void sendWelcome(ClientSession* c);
    void doKick(ClientSession* c, const QString& reason, bool fromServer, bool ban, int minutes = 0);
    int channelOfUser(int userId) const;
    bool isAdmin(const ClientSession* c) const;
    void removeFromChannels(int userId);
    void addToChannel(int userId, int channelId);
    SvrChan chanFromJson(const QJsonObject& o) const;
    QJsonObject chanToJson(const SvrChan& c) const;
    void dumpBansIfNeeded();
};
