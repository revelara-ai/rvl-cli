package hipstershop;

import com.acme.vendor.Widget;
import hipstershop.Demo.Ad;
import hipstershop.Demo.AdResponse;
import java.util.List;

// Builds protobuf messages through the classes protoc generates from
// demo.proto. Neither builder call does I/O; the vendor Widget's builder is
// not a message and stays a call site.
public final class AdService {
    AdResponse reply(List<Ad> ads) {
        return AdResponse.newBuilder().addAllAds(ads).build();
    }

    Ad camera() {
        return Ad.newBuilder()
                .setRedirectUrl("/product/2ZYFJ3GM2N")
                .setText("Film camera for sale. 50% off.")
                .build();
    }

    Widget widget() {
        return Widget.newBuilder().build();
    }
}
