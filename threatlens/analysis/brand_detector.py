from threats.models import Brand


def detect_brand_impersonation(domain):

    brands = Brand.objects.all()

    for brand in brands:

        brand_domain = brand.official_domain.split('.')[0]

        if brand_domain in domain and brand.official_domain not in domain:

            return brand.name

    return None