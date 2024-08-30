# URL Güvenlik Tarama Uygulaması

Bu proje, kullanıcıların belirli bir web sayfasından URL'leri çıkarmasına ve VirusTotal API'sini kullanarak potansiyel kötü amaçlı yazılımlara karşı taramasına olanak tanıyan Flask ile oluşturulmuş web tabanlı bir uygulamadır.
## Özellikler

- **URL Çıkarma:** Uygulama, sağlanan bir web sayfasından tüm benzersiz URL'leri çıkarır.
- **VirusTotal Entegrasyonu:** Çıkarılan her URL, potansiyel olarak kötü amaçlı olup olmadığını belirlemek için VirusTotal API kullanılarak taranır.
- **Kullanıcı Dostu Arayüz:** Uygulama, URL'leri girmek ve tarama sonuçlarını görüntülemek için sezgisel bir web arayüzü sağlar.

## Önkoşullar

Uygulamayı çalıştırmadan önce aşağıdakilerin kurulu olduğundan emin olun:

- Python 3.9-slim
- Flask
- Requests
- BeautifulSoup4

## Kurulum

**Clone the repository:**

   ```bash
   git clone https://github.com/jrkurban/dataflowx.git
   cd guvenli_link
