#pragma once

#include <QObject>
#include <QMap>
#include <QString>
#include <QSet>
#include <QHash>
#include <QByteArray>
#include <QHostAddress>
#include <QSslCertificate>
#include <QSslKey>

class QTcpServer;
class QTcpSocket;
class ServerCore;

// Interface administrativa TLS. Desligada por padrão e, quando habilitada,
// deve permanecer em loopback salvo decisão explícita do operador.
class ServerQuery : public QObject {
    Q_OBJECT
public:
    explicit ServerQuery(ServerCore* core, QObject* parent = nullptr);

    bool start(quint16 port, const QHostAddress& bindAddress = QHostAddress::LocalHost);
    void setCredentials(const QString& user, const QString& pass);
    void setTlsConfiguration(const QSslCertificate& certificate, const QSslKey& privateKey);
    QString generatedPassword() const { return m_generatedPlaintext; }
    QString passwordHashForStorage() const { return m_passHash; }

    static QString escape(const QString& v);
    static QString unescape(const QString& v);

private:
    void onNew();
    void onRead(QTcpSocket* s);
    void handleLine(QTcpSocket* s, const QString& line);
    void handleArgs(QTcpSocket* s, const QString& cmd,
                    const QMap<QString, QString>& args);
    bool allowLoginAttempt(QTcpSocket* s);

    void sendLine(QTcpSocket* s, const QString& line);
    void ok(QTcpSocket* s);
    void error(QTcpSocket* s, int id, const QString& msg);
    bool needAuth(QTcpSocket* s, const QString& cmd);

    static QMap<QString, QString> parseArgs(const QString& rest);

    ServerCore* m_core;
    QTcpServer* m_srv = nullptr;
    QString m_user = QStringLiteral("serveradmin");
    QString m_passHash;
    QString m_generatedPlaintext;
    bool m_passGenerated = false;
    QSslCertificate m_certificate;
    QSslKey m_privateKey;
    QSet<QTcpSocket*> m_authed;
    QHash<QTcpSocket*, QByteArray> m_bufs;
    QHash<QString, QList<qint64>> m_loginAttemptsByIp;
};
