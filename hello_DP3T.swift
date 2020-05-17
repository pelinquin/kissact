// Hello World! code for iOS DP3T Contact Tracing
// Do not forget to add BLE & Location in info.plist and reference DP3TSDK

import DP3TSDK_CALIBRATION
import SnapKit
import UIKit

@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {
    var w: UIWindow?

    func application(_ application: UIApplication, didFinishLaunchingWithOptions _: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        try! DP3TTracing.initialize(with: .discovery("org.dpppt.demo", enviroment: .dev),
                                    mode: .calibration(identifierPrefix: "", appVersion:"N/A"))
        if application.applicationState != .background { initWindow()}
        try? DP3TTracing.startTracing()
        return true
    }
    func initWindow() {
        w = UIWindow(frame: UIScreen.main.bounds)
        w?.makeKey()
        w?.rootViewController = viewController()
        w?.makeKeyAndVisible()
    }
    func applicationWillEnterForeground(_: UIApplication) {
        if w == nil { initWindow() }
    }
}

class viewController: UIViewController {
    let stac = UIStackView()
    let stat = UILabel()
    let epid = UILabel()
    let date = UILabel()
    let dist = UILabel()
    let txtx = UILabel()
    let rssi = UILabel()
    
    init() { super.init(nibName: nil, bundle: nil) }
    required init?(coder _: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func viewDidLoad() {
        super.viewDidLoad()
        self.view.backgroundColor = .systemBackground
        view.addSubview(stac)
        stac.snp.makeConstraints { make in
            make.left.right.bottom.equalTo(self.view.layoutMarginsGuide)
            make.top.equalTo(self.view.layoutMarginsGuide).inset(12)
        }
        stac.axis = .vertical
        epid.font = epid.font.withSize(20)
        epid.numberOfLines = 17
        do {
            let resp = try DP3TTracing.getHandshakes(request: HandshakeRequest(offset: 0, limit: 1))
            if resp.handshakes != [] { disp(resp.handshakes[0]) } else { disp_init() }
        } catch { print ("ERROR") }
        stac.addArrangedSubview(stat)
        stac.addArrangedSubview(epid)
        stac.addArrangedSubview(date)
        stac.addArrangedSubview(dist)
        stac.addArrangedSubview(txtx)
        stac.addArrangedSubview(rssi)
        DP3TTracing.delegate = self
    }
    
    func disp(_ hs: HandshakeModel) {
        DP3TTracing.status { result in
            switch result {
                case let .success(state):
                    stat.text = "Contacts: \(state.numberOfContacts)   Handshakes: \(state.numberOfHandshakes)"
                case .failure: break
            }
        }
        epid.text = hs.ephID.hexEncodedString
        date.text = hs.timestamp.stringVal
        dist.text = hs.distance == nil ? "--" : String(format: "%.2fm", hs.distance!)
        txtx.text = hs.TXPowerlevel == nil ? " -- " : String(format: "%.2f", hs.TXPowerlevel!)
        rssi.text = hs.RSSI == nil ? " -- " : String(format: "%.2f", hs.RSSI!)
    }
    
    func disp_init() {
        stat.text = "--"
        epid.text = "--"
        date.text = "--"
        dist.text = "--"
        txtx.text = "--"
        rssi.text = "--"
    }
}

extension Date {
    var stringVal: String {
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "MMMMd  HH:mm:ss "
        return dateFormatter.string(from: self)
    }
}

extension Data {
    var hexEncodedString: String {
        return map { String(format: "%02hhX\n", $0) }.joined()
    }
}

extension viewController: DP3TTracingDelegate {
    func DP3TTracingStateChanged(_: TracingState) {}
    func didAddHandshake(_ hs: HandshakeModel) { disp(hs) }
}
