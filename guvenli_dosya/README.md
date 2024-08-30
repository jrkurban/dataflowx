# Dosya Güvenlik Tarama Uygulaması

Bu proje, bir Linux ortamında belirli bir dizini sürekli izleyen ve bu dizine eklenen her yeni dosyayı VirusTotal API’si kullanarak tarayan bir Python uygulamasıdır. Uygulama, tarama sonuçlarını ayrı bir dizinde metin dosyaları olarak saklar ve Docker içinde çalışacak şekilde paketlenmiştir.

## Proje Yapısı

- **main.py**: Uygulamanın ana Python betiği. Dosya izleme ve tarama işlemleri burada gerçekleştirilir.
- **Dockerfile**: Uygulamayı Docker içinde çalıştırmak için kullanılan Docker yapılandırma dosyası.
- **watch/**: İzlenecek dizin. Bu dizine yeni dosyalar eklendiğinde tarama işlemi başlar.
- **results/**: Tarama sonuçlarının kaydedileceği dizin. Her bir dosya için tarama sonuçları ayrı bir metin dosyası olarak saklanır.

## Kullanım

### Geliştirme Ortamının Kurulumu

1. **Gereksinimleri Kurun**
   - Docker yüklü olmalıdır.
   - Docker'ı yüklemek için [resmi Docker dökümantasyonunu](https://docs.docker.com/get-docker/) takip edebilirsiniz.

2. **Proje Dosyalarını Klonlayın**
   ```bash
   git clone https://github.com/jrkurban/dataflowx.git
   cd guvenli_dosya

3. **Uygulamayı çalıştırın**
    ```bash
    docker-compose up --build
