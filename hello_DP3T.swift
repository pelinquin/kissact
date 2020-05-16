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
    let stackView = UIStackView()
    let epid = UILabel()
    let date = UILabel()
    let dist = UILabel()
    let txtx = UILabel()
    let rssi = UILabel()
    
    init() {
        super.init(nibName: nil, bundle: nil)
    }
    required init?(coder _: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func viewDidLoad() {
        super.viewDidLoad()
        Default.shared.tracingMode = .active
        self.view.backgroundColor = .systemBackground
        view.addSubview(stackView)
        stackView.snp.makeConstraints { make in
            make.left.right.bottom.equalTo(self.view.layoutMarginsGuide)
            make.top.equalTo(self.view.layoutMarginsGuide).inset(12)
        }
        stackView.axis = .vertical
        do {
            epid.text = "EPHID"
            epid.font = epid.font.withSize(15)
            date.text = "DATE"
            dist.text = "DISTANCE"
            txtx.text = "TX"
            rssi.text = "RSSI"
            stackView.addArrangedSubview(epid)
            stackView.addArrangedSubview(date)
            stackView.addArrangedSubview(dist)
            stackView.addArrangedSubview(txtx)
            stackView.addArrangedSubview(rssi)
            let button = UIButton()
            button.setTitleColor(.systemBlue, for: .normal)
            button.setTitle("Update ephId", for: .normal)
            button.addTarget(self, action: #selector(go), for: .touchUpInside)
            stackView.addArrangedSubview(button)
        }
    }

    @objc func go() {
        do {
            let req = HandshakeRequest(offset: 0, limit: 1)
            let hs: HandshakeModel
            let resp = try DP3TTracing.getHandshakes(request: req)
            print ("HANDSHAKE", resp.handshakes.count)
            hs = resp.handshakes[0]
            epid.text = hs.ephID.hexEncodedString
            date.text = hs.timestamp.stringVal
            dist.text = hs.distance == nil ? "--" : String(format: "%.2fm", hs.distance!)
            txtx.text = hs.TXPowerlevel == nil ? " -- " : String(format: "%.2f", hs.TXPowerlevel!)
            rssi.text = hs.RSSI == nil ? " -- " : String(format: "%.2f", hs.RSSI!)
        } catch { print ("ERROR") }
    }
}

extension Date {
    var stringVal: String {
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "HH:mm:ss "
        return dateFormatter.string(from: self)
    }
}

extension Data {
    var hexEncodedString: String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}

class Default {
    static var shared = Default()
    var store = UserDefaults.standard
    
    enum TracingMode: Int {
        case none = 0
        case active = 1
        case activeReceiving = 2
        case activeAdvertising = 3
    }
    var tracingMode: TracingMode {
        get {
            let mode = (store.object(forKey: "org.dpppt.sampleapp.tracingMode") as? Int) ?? 0
            return TracingMode(rawValue: mode) ?? .none
        }
        set(newValue) {
            store.set(newValue.rawValue, forKey: "org.dpppt.sampleapp.tracingMode")
        }
    }
}
