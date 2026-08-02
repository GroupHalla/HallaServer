#pragma once

#include <QObject>
#include <QMap>
#include <QString>
#include <QSet>
#include <QHash>
#include <QByteArray>

class QTcpServer;
class QTcpSocket;
class ServerCore;

// ============================================================================
// ServerQuery do Halla — interface de administração em modo texto sobre TCP,
// inspirada no TeamSpeak 3 ServerQuery (porta padrão 10011).
//
// Comandos: login, logout, use, version, serverinfo, clientlist, channellist,
// clientkick, banclient, banlist, banadd, bandel, gm, help, quit.
// Respostas no formato chave=valor com quebra de linha e "error id=N msg=...".
// ============================================================================
class ServerQuery : public QObject {
    Q_OBJECT
public:
    explicit ServerQuery(ServerCore* core, QObject* parent = nullptr);

    bool start(quint16 port);                    // 0 = desligado
    void setCredentials(const QString& user, const QString& pass);
    QString generatedPassword() const { return m_pass; } // gerada se não houver

    static QString escape(const QString& v);
    static QString unescape(const QString& v);

private:
    void onNew();
    void onRead(QTcpSocket* s);
    void handleLine(QTcpSocket* s, const QString& line);
    void handleArgs(QTcpSocket* s, const QString& cmd,
                    const QMap<QString, QString>& args);

    void sendLine(QTcpSocket* s, const QString& line);
    void ok(QTcpSocket* s);
    void error(QTcpSocket* s, int id, const QString& msg);
    bool needAuth(QTcpSocket* s, const QString& cmd);

    static QMap<QString, QString> parseArgs(const QString& rest);

    ServerCore* m_core;
    QTcpServer* m_srv = nullptr;
    QString m_user = QStringLiteral("serveradmin");
    QString m_pass;
    bool m_passGenerated = false;
    QSet<QTcpSocket*> m_authed;
    QHash<QTcpSocket*, QByteArray> m_bufs;
};
