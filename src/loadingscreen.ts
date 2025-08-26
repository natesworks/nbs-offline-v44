import { base } from "./definitions";
import { Offsets } from "./offsets";

export function customLoadingScreen() {
    Interceptor.attach(base.add(Offsets.LoadingScreenUpdateLoadingProgress),
        {
            onEnter(args) {
                this.stringFormatHook = Interceptor.attach(base.add(Offsets.StringFormat),
                    {
                        onEnter(args) {
                            
                        },
                    });
            },
            onLeave() {
                this.stringFormatHook.detach();
            },
        });
}