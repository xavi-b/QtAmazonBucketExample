#include <QCoreApplication>
#include <QDebug>
#include <QFile>
#include <QFileInfo>
#include <QMessageAuthenticationCode>
#include <QMimeDatabase>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    // change by your S3 access key
    QString s3Key = "";
    // change by your S3 secret key
    QString s3Secret = "";
    // change by your bucket name
    QString s3Bucket = "";
    // change by your bucket location
    QString bucketLocation = "eu-west-3";
    // change by the location in your bucket
    QString remotePath = "/test2/adwsfdwq";

    QString endpoint = "s3-" + bucketLocation + ".amazonaws.com";
    QString yyyymmdd = QDateTime::currentDateTimeUtc().toString("yyyyMMdd");
    QString isoDate = QDateTime::currentDateTimeUtc().toString("yyyyMMddThhmmssZ");

    QByteArray data;

    QString contentLength = QString::number(0);
    QString contentHash = QCryptographicHash::hash(data, QCryptographicHash::Sha256).toHex();

    qDebug() << "----contentHash";
    qDebug().noquote() << contentHash;

    QString canonicalRequest = "DELETE\n/" + s3Bucket + remotePath
                               + "\n\ncontent-length:" + contentLength + "\nhost:" + endpoint
                               + "\nx-amz-content-sha256:" + contentHash + "\nx-amz-date:" + isoDate
                               + "\n\ncontent-length;host;x-amz-content-sha256;x-amz-date\n"
                               + contentHash;
    QString canonicalRequestHash = QCryptographicHash::hash(canonicalRequest.trimmed().toUtf8(), QCryptographicHash::Sha256).toHex();

    QString stringToSign = "AWS4-HMAC-SHA256\n" + isoDate + "\n" + yyyymmdd + "/" + bucketLocation + "/s3/aws4_request\n" + canonicalRequestHash + "";

    qDebug() << "----canonicalRequest";
    qDebug().noquote() << canonicalRequest;
    qDebug() << "----stringToSign";
    qDebug().noquote() << stringToSign;

    QByteArray DateKey = QMessageAuthenticationCode::hash(yyyymmdd.toUtf8(), ("AWS4" + s3Secret).toUtf8(), QCryptographicHash::Sha256);
    QByteArray DateRegionKey = QMessageAuthenticationCode::hash(bucketLocation.toUtf8(), DateKey, QCryptographicHash::Sha256);
    QByteArray DateRegionServiceKey = QMessageAuthenticationCode::hash("s3", DateRegionKey, QCryptographicHash::Sha256);
    QByteArray SigningKey = QMessageAuthenticationCode::hash("aws4_request", DateRegionServiceKey, QCryptographicHash::Sha256);
    QString signature = QMessageAuthenticationCode::hash(stringToSign.toUtf8(), SigningKey, QCryptographicHash::Sha256).toHex();

    QString authoriz = "AWS4-HMAC-SHA256 Credential=" + s3Key  + "/" + yyyymmdd  + "/" + bucketLocation  + "/s3/aws4_request, SignedHeaders=content-length;host;x-amz-content-sha256;x-amz-date, Signature=" + signature;

    qDebug() << "----authoriz";
    qDebug().noquote() << authoriz;

    QUrl url = "https://" + endpoint + "/" + s3Bucket + remotePath;

    QNetworkAccessManager manager;
    QNetworkRequest req(url);
    req.setRawHeader("Host", endpoint.toUtf8());
    req.setRawHeader("Content-Length", contentLength.toUtf8());
    req.setRawHeader("x-amz-date", isoDate.toUtf8());
    req.setRawHeader("x-amz-content-sha256", contentHash.toUtf8());
    req.setRawHeader("Authorization", authoriz.toUtf8());
    auto reply = manager.sendCustomRequest(req, "DELETE");
    QObject::connect(reply, &QNetworkReply::errorOccurred, [&](){
        qDebug() << "----Request headers";
        for(auto r : req.rawHeaderList())
            qDebug() << r << " " << req.rawHeader(r);
        qDebug() << "----Reply headers";
        for(auto r : reply->rawHeaderList())
            qDebug() << r << " " << reply->rawHeader(r);
        qDebug() << reply->errorString();
    });

    QObject::connect(reply, &QNetworkReply::finished, [&](){
        qDebug() << "----Reply";
        qDebug() << reply->readAll();
        a.quit();
    });

    return a.exec();
}
